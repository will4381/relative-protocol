import Foundation

/// Controls how packet-tunnel MTU settings are applied to `NEPacketTunnelNetworkSettings`.
public enum TunnelMTUStrategy: Sendable, Equatable {
    /// Assigns an explicit MTU to the TUN interface.
    case fixed(Int)
    /// Lets NetworkExtension derive the TUN MTU from the active physical interface MTU minus tunnel overhead.
    case automaticTunnelOverhead(Int)

    /// Compatibility-first default when the host app does not provide an explicit MTU policy.
    public static let recommendedGeneric = TunnelMTUStrategy.fixed(1_280)
    /// Reasonable worst-case overhead for WireGuard-like UDP tunnels over IPv6.
    public static let recommendedWireGuardLikeOverhead = TunnelMTUStrategy.automaticTunnelOverhead(80)

    /// Returns the MTU hint used for local buffers when the interface MTU is not explicitly fixed.
    public var bufferMTUHint: Int {
        switch self {
        case .fixed(let mtu):
            return max(256, mtu)
        case .automaticTunnelOverhead:
            return TunnelMTUStrategy.recommendedGeneric.bufferMTUHint
        }
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
