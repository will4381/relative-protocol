import Foundation

internal struct ServiceAttribution: Sendable, Equatable {
    let family: String
    let confidence: Double
    let sourceMask: UInt16
}

internal enum ServiceAttributionSourceMask {
    static let classification: UInt16 = 1 << 0
    static let dnsAssociation: UInt16 = 1 << 1
    static let registrableDomain: UInt16 = 1 << 2
    static let tlsServerName: UInt16 = 1 << 3
    static let dnsCname: UInt16 = 1 << 4
    static let dnsQueryName: UInt16 = 1 << 5
}

internal enum ServiceAttributionBuilder {
    static func make(flowContext: PacketAnalyticsPipeline.FlowContextView) -> ServiceAttribution? {
        var sourceMask: UInt16 = 0
        let classification = normalizedLabel(flowContext.classification)
        let associatedDomain = normalizedDomain(flowContext.associatedDomain)
        let registrableDomain = normalizedDomain(flowContext.registrableDomain)
        let tlsDomain = normalizedDomain(flowContext.tlsServerName)
        let cnameDomain = normalizedDomain(flowContext.dnsCname)
        let queryDomain = normalizedDomain(flowContext.dnsQueryName)

        let family = classification
            ?? associatedDomain
            ?? registrableDomain
            ?? tlsDomain
            ?? cnameDomain
            ?? queryDomain
        guard let family else {
            return nil
        }

        if classification == family {
            sourceMask |= ServiceAttributionSourceMask.classification
        }
        if associatedDomain == family {
            sourceMask |= ServiceAttributionSourceMask.dnsAssociation
        }
        if registrableDomain == family {
            sourceMask |= ServiceAttributionSourceMask.registrableDomain
        }
        if tlsDomain == family {
            sourceMask |= ServiceAttributionSourceMask.tlsServerName
        }
        if cnameDomain == family {
            sourceMask |= ServiceAttributionSourceMask.dnsCname
        }
        if queryDomain == family {
            sourceMask |= ServiceAttributionSourceMask.dnsQueryName
        }

        var confidence: Double
        switch family {
        case classification:
            confidence = 0.82
        case associatedDomain:
            confidence = 0.76
        case registrableDomain:
            confidence = 0.7
        case tlsDomain:
            confidence = 0.66
        case cnameDomain:
            confidence = 0.62
        default:
            confidence = 0.58
        }

        let corroboratingSources = sourceMask.nonzeroBitCount
        if corroboratingSources > 1 {
            confidence += Double(corroboratingSources - 1) * 0.05
        }
        return ServiceAttribution(
            family: family,
            confidence: min(confidence, 0.97),
            sourceMask: sourceMask
        )
    }

    private static func normalizedLabel(_ value: String?) -> String? {
        if let value = value?.lowercased(), !value.isEmpty {
            return value
        }
        return nil
    }

    private static func normalizedDomain(_ value: String?) -> String? {
        if let value = DomainNormalizer.registrableDomain(from: value) {
            return value.lowercased()
        }
        return normalizedLabel(value)
    }
}
