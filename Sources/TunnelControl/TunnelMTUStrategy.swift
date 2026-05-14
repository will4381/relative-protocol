import Foundation

/// Controls how packet-tunnel MTU settings are applied to `NEPacketTunnelNetworkSettings`.
public enum TunnelMTUStrategy: Sendable, Equatable {
    /// Assigns an explicit MTU to the TUN interface.
    case fixed(Int)
    /// Lets NetworkExtension derive the TUN MTU from the active physical interface MTU minus tunnel overhead.
    case automaticTunnelOverhead(Int)

    /// Compatibility-first default when the host app does not provide an explicit MTU policy.
    public static let recommendedGeneric = TunnelMTUStrategy.fixed(1_280)
    /// Smallest packet buffer hint accepted from compatibility callers.
    static let minimumBufferMTUHint = 256
    /// Smallest runtime MTU accepted by the packet tunnel.
    static let minimumRuntimeMTU = 1_280
    /// Largest IPv4 packet size and a safe upper bound for interface MTU hints.
    static let maximumInterfaceMTU = 65_535
    /// Largest overhead value accepted before installing NetworkExtension settings.
    static let maximumTunnelOverheadBytes = 65_535
    /// Internal packet buffer ceiling used when NetworkExtension derives the interface MTU.
    public static let automaticBufferMTUHint = 1_500
    /// Reasonable worst-case overhead for WireGuard-like UDP tunnels over IPv6.
    public static let recommendedWireGuardLikeOverhead = TunnelMTUStrategy.automaticTunnelOverhead(80)

    /// Returns the MTU hint used for local buffers when the interface MTU is not explicitly fixed.
    public var bufferMTUHint: Int {
        switch self {
        case .fixed(let mtu):
            return Self.clampedInterfaceMTU(mtu, minimum: Self.minimumBufferMTUHint)
        case .automaticTunnelOverhead:
            return TunnelMTUStrategy.automaticBufferMTUHint
        }
    }

    func normalizedForProvider() -> TunnelMTUStrategy {
        switch self {
        case .fixed(let mtu):
            return .fixed(Self.clampedInterfaceMTU(mtu, minimum: Self.minimumBufferMTUHint))
        case .automaticTunnelOverhead(let overhead):
            return .automaticTunnelOverhead(min(max(0, overhead), Self.maximumTunnelOverheadBytes))
        }
    }

    static func clampedInterfaceMTU(_ mtu: Int, minimum: Int) -> Int {
        min(max(minimum, mtu), Self.maximumInterfaceMTU)
    }

    var providerConfiguration: [String: Any] {
        switch self {
        case .fixed(let mtu):
            return [
                "mtuStrategy": "fixed",
                "mtu": mtu
            ]
        case .automaticTunnelOverhead(let overhead):
            return [
                "mtuStrategy": "automaticTunnelOverhead",
                "tunnelOverheadBytes": overhead
            ]
        }
    }
}
