import Foundation
@preconcurrency import NetworkExtension
@testable import TunnelControl

/// Test-only simulator for the documented Network Extension packet-tunnel contract.
///
/// Scope:
/// - Mirrors the provider/session/packet-flow API shape that Apple documents.
/// - Uses real NetworkExtension settings objects where Apple exposes concrete types.
/// - Does not pretend to emulate the iOS kernel route table, extension process host, entitlement checks, or packetFlow
///   implementation. Those remain physical-device validation gates.
///
/// Docs:
/// - https://developer.apple.com/documentation/networkextension/nepackettunnelprovider
/// - https://developer.apple.com/documentation/networkextension/netunnelprovider
/// - https://developer.apple.com/documentation/networkextension/nepackettunnelflow
final class NetworkExtensionContractSimulator {
    enum Error: Swift.Error, Equatable {
        case invalidStartStatus(SimulatedVPNStatus)
        case invalidStopStatus(SimulatedVPNStatus)
        case settingsApplicationFailed(String)
    }

    struct StartResult {
        let profile: TunnelProfile
        let settings: NEPacketTunnelNetworkSettings
        let options: [String: NSObject]?
    }

    enum SimulatedVPNStatus: String, Equatable {
        case invalid
        case disconnected
        case connecting
        case connected
        case reasserting
        case disconnecting
    }

    struct Event: Equatable {
        let name: String
        let status: SimulatedVPNStatus
        let stopReasonRawValue: Int?
        let messageByteCount: Int?

        init(
            _ name: String,
            status: SimulatedVPNStatus,
            stopReasonRawValue: Int? = nil,
            messageByteCount: Int? = nil
        ) {
            self.name = name
            self.status = status
            self.stopReasonRawValue = stopReasonRawValue
            self.messageByteCount = messageByteCount
        }
    }

    var status: SimulatedVPNStatus { state.status }
    private(set) var packetFlow = MockPacketTunnelFlow()
    private(set) var appliedSettings: [NEPacketTunnelNetworkSettings] = []
    private(set) var events: [Event] = []
    var nextSettingsError: String?
    var appMessageHandler: ((Data) -> Data?)?

    private var state = State()
    private var providerConfiguration: [String: Any]

    init(providerConfiguration: [String: Any]) {
        self.providerConfiguration = providerConfiguration
        events.append(Event("initialized", status: state.status))
    }

    /// Simulates `NEPacketTunnelProvider.startTunnel(options:completionHandler:)`.
    /// Docs: https://developer.apple.com/documentation/networkextension/nepackettunnelprovider/starttunnel(options:completionhandler:)
    func startTunnel(options: [String: NSObject]? = nil) throws -> StartResult {
        guard state.status == .disconnected else {
            throw Error.invalidStartStatus(state.status)
        }

        state.status = .connecting
        events.append(Event("startTunnel", status: state.status))

        do {
            let profile = try TunnelProfile.validatedRuntimeProfile(providerConfiguration: providerConfiguration)
            let settings = TunnelNetworkSettingsFactory.makeSettings(profile: profile)
            try setTunnelNetworkSettings(settings)
            state.status = .connected
            events.append(Event("connected", status: state.status))
            return StartResult(profile: profile, settings: settings, options: options)
        } catch let error as Error {
            state.status = .disconnected
            events.append(Event("startTunnelFailed", status: state.status))
            throw error
        } catch {
            state.status = .disconnected
            events.append(Event("startTunnelFailed", status: state.status))
            throw error
        }
    }

    /// Simulates `NETunnelProvider.setTunnelNetworkSettings(_:completionHandler:)`.
    /// Docs: https://developer.apple.com/documentation/networkextension/netunnelprovider/settunnelnetworksettings(_:completionhandler:)
    func setTunnelNetworkSettings(_ settings: NEPacketTunnelNetworkSettings?) throws {
        if let nextSettingsError {
            self.nextSettingsError = nil
            throw Error.settingsApplicationFailed(nextSettingsError)
        }

        if let settings {
            appliedSettings.append(settings)
            events.append(Event("setTunnelNetworkSettings", status: state.status))
        } else {
            appliedSettings.removeAll()
            events.append(Event("clearTunnelNetworkSettings", status: state.status))
        }
    }

    /// Simulates `NEPacketTunnelProvider.stopTunnel(with:completionHandler:)`.
    /// Docs: https://developer.apple.com/documentation/networkextension/nepackettunnelprovider/stoptunnel(with:completionhandler:)
    func stopTunnel(with reason: NEProviderStopReason) throws {
        guard state.status == .connected || state.status == .connecting || state.status == .reasserting else {
            throw Error.invalidStopStatus(state.status)
        }

        state.status = .disconnecting
        events.append(Event("stopTunnel", status: state.status, stopReasonRawValue: reason.rawValue))
        state.status = .disconnected
        events.append(Event("disconnected", status: state.status, stopReasonRawValue: reason.rawValue))
    }

    /// Simulates `NEPacketTunnelProvider.cancelTunnelWithError(_:)`.
    /// Docs: https://developer.apple.com/documentation/networkextension/nepackettunnelprovider/canceltunnelwitherror(_:)
    func cancelTunnelWithError(_ error: Swift.Error?) {
        _ = error
        state.status = .disconnecting
        events.append(Event("cancelTunnelWithError", status: state.status))
        state.status = .disconnected
        events.append(Event("disconnected", status: state.status))
    }

    /// Simulates `NETunnelProvider.reasserting`.
    /// Docs: https://developer.apple.com/documentation/networkextension/netunnelprovider/reasserting
    func setReasserting(_ reasserting: Bool) {
        if reasserting, state.status == .connected {
            state.status = .reasserting
            events.append(Event("reasserting", status: state.status))
        } else if !reasserting, state.status == .reasserting {
            state.status = .connected
            events.append(Event("connected", status: state.status))
        }
    }

    /// Simulates `NETunnelProvider.handleAppMessage(_:completionHandler:)`.
    /// Docs: https://developer.apple.com/documentation/networkextension/netunnelprovider/handleappmessage(_:completionhandler:)
    func handleAppMessage(_ messageData: Data) -> Data? {
        events.append(Event("handleAppMessage", status: state.status, messageByteCount: messageData.count))
        return appMessageHandler?(messageData)
    }

    private struct State {
        var status: SimulatedVPNStatus = .disconnected
    }
}

/// Test double for the behavior the package consumes from `NEPacketTunnelFlow`.
///
/// Docs:
/// - https://developer.apple.com/documentation/networkextension/nepackettunnelflow/readpackets(completionhandler:)
/// - https://developer.apple.com/documentation/networkextension/nepackettunnelflow/writepackets(_:withprotocols:)
/// - https://developer.apple.com/documentation/networkextension/nepackettunnelflow/readpacketobjects(completionhandler:)
/// - https://developer.apple.com/documentation/networkextension/nepackettunnelflow/writepacketobjects(_:)
final class MockPacketTunnelFlow {
    struct PacketBatch: Equatable {
        let packets: [Data]
        let protocols: [NSNumber]

        init(packets: [Data], protocols: [NSNumber]) {
            self.packets = packets
            self.protocols = protocols
        }
    }

    struct PacketObjectBatch {
        let packets: [NEPacket]
    }

    private(set) var writtenBatches: [PacketBatch] = []
    private(set) var writtenPacketObjectBatches: [PacketObjectBatch] = []
    private(set) var readRequests = 0
    private(set) var packetObjectReadRequests = 0
    var writeResults: [Bool] = []

    private var pendingRead: (([Data], [NSNumber]) -> Void)?
    private var pendingPacketObjectRead: (([NEPacket]) -> Void)?
    private var queuedBatches: [PacketBatch] = []
    private var queuedPacketObjectBatches: [PacketObjectBatch] = []

    func readPackets(completionHandler: @escaping ([Data], [NSNumber]) -> Void) {
        readRequests += 1
        if !queuedBatches.isEmpty {
            let batch = queuedBatches.removeFirst()
            completionHandler(batch.packets, batch.protocols)
            return
        }
        pendingRead = completionHandler
    }

    func enqueueReadBatch(_ batch: PacketBatch) {
        if let pendingRead {
            self.pendingRead = nil
            pendingRead(batch.packets, batch.protocols)
        } else {
            queuedBatches.append(batch)
        }
    }

    func writePackets(_ packets: [Data], withProtocols protocols: [NSNumber]) -> Bool {
        writtenBatches.append(PacketBatch(packets: packets, protocols: protocols))
        if writeResults.isEmpty {
            return true
        }
        return writeResults.removeFirst()
    }

    func readPacketObjects(completionHandler: @escaping ([NEPacket]) -> Void) {
        packetObjectReadRequests += 1
        if !queuedPacketObjectBatches.isEmpty {
            completionHandler(queuedPacketObjectBatches.removeFirst().packets)
            return
        }
        pendingPacketObjectRead = completionHandler
    }

    func enqueuePacketObjectReadBatch(_ batch: PacketObjectBatch) {
        if let pendingPacketObjectRead {
            self.pendingPacketObjectRead = nil
            pendingPacketObjectRead(batch.packets)
        } else {
            queuedPacketObjectBatches.append(batch)
        }
    }

    func writePacketObjects(_ packets: [NEPacket]) -> Bool {
        writtenPacketObjectBatches.append(PacketObjectBatch(packets: packets))
        if writeResults.isEmpty {
            return true
        }
        return writeResults.removeFirst()
    }
}

struct TunnelNetworkSettingsSnapshot: Equatable {
    enum DNSKind: Equatable {
        case none
        case cleartext
        case tls(serverName: String?)
        case https(serverURL: String?)
    }

    let tunnelRemoteAddress: String
    let ipv4Addresses: [String]
    let ipv4SubnetMasks: [String]
    let ipv4IncludedRoutes: [IPv4Route]
    let ipv6Addresses: [String]
    let ipv6PrefixLengths: [Int]
    let ipv6IncludedRoutes: [IPv6Route]
    let dnsKind: DNSKind
    let dnsServers: [String]
    let dnsMatchDomains: [String]?
    let dnsMatchDomainsNoSearch: Bool
    let mtu: Int?
    let tunnelOverheadBytes: Int?

    var hasIPv4DefaultRoute: Bool {
        ipv4IncludedRoutes.contains(IPv4Route(destinationAddress: "0.0.0.0", destinationSubnetMask: "0.0.0.0"))
    }

    var hasIPv6DefaultRoute: Bool {
        ipv6IncludedRoutes.contains(IPv6Route(destinationAddress: "::", destinationNetworkPrefixLength: 0))
    }

    static func capture(_ settings: NEPacketTunnelNetworkSettings) -> TunnelNetworkSettingsSnapshot {
        let dnsSettings = settings.dnsSettings
        let dnsKind: DNSKind
        if let dnsTLS = dnsSettings as? NEDNSOverTLSSettings {
            dnsKind = .tls(serverName: dnsTLS.serverName)
        } else if let dnsHTTPS = dnsSettings as? NEDNSOverHTTPSSettings {
            dnsKind = .https(serverURL: dnsHTTPS.serverURL?.absoluteString)
        } else if dnsSettings != nil {
            dnsKind = .cleartext
        } else {
            dnsKind = .none
        }

        return TunnelNetworkSettingsSnapshot(
            tunnelRemoteAddress: settings.tunnelRemoteAddress,
            ipv4Addresses: settings.ipv4Settings?.addresses ?? [],
            ipv4SubnetMasks: settings.ipv4Settings?.subnetMasks ?? [],
            ipv4IncludedRoutes: (settings.ipv4Settings?.includedRoutes ?? []).map(IPv4Route.capture),
            ipv6Addresses: settings.ipv6Settings?.addresses ?? [],
            ipv6PrefixLengths: (settings.ipv6Settings?.networkPrefixLengths ?? []).map(\.intValue),
            ipv6IncludedRoutes: (settings.ipv6Settings?.includedRoutes ?? []).map(IPv6Route.capture),
            dnsKind: dnsKind,
            dnsServers: dnsSettings?.servers ?? [],
            dnsMatchDomains: dnsSettings?.matchDomains,
            dnsMatchDomainsNoSearch: dnsSettings?.matchDomainsNoSearch ?? false,
            mtu: settings.mtu?.intValue,
            tunnelOverheadBytes: settings.tunnelOverheadBytes?.intValue
        )
    }

    struct IPv4Route: Equatable {
        let destinationAddress: String
        let destinationSubnetMask: String

        static func capture(_ route: NEIPv4Route) -> IPv4Route {
            IPv4Route(
                destinationAddress: route.destinationAddress,
                destinationSubnetMask: route.destinationSubnetMask
            )
        }
    }

    struct IPv6Route: Equatable {
        let destinationAddress: String
        let destinationNetworkPrefixLength: Int

        static func capture(_ route: NEIPv6Route) -> IPv6Route {
            IPv6Route(
                destinationAddress: route.destinationAddress,
                destinationNetworkPrefixLength: route.destinationNetworkPrefixLength.intValue
            )
        }
    }
}
