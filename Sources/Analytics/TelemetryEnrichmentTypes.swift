import Foundation

/// Source that produced a best-effort domain association for hostless traffic.
public enum DetectorAssociationSource: String, Codable, Sendable, Equatable {
    case dnsAnswer
    case dnsQuery
    case dnsCname
    case tlsServerName
    case registrableDomain
    case classification
}

/// Coarse network regime bucket attached to detector-facing records when path tracking is enabled.
public enum PathInterfaceClass: String, Codable, Sendable, Equatable {
    case unavailable
    case wifi
    case cellular
    case wiredEthernet
    case loopback
    case other
    case mixed
}
