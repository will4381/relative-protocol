import Foundation

/// Coarse detector feature families used to keep enrichment work proportional to installed detector needs.
public struct DetectorFeatureFamily: OptionSet, Sendable, Hashable {
    public let rawValue: UInt64

    public init(rawValue: UInt64) {
        self.rawValue = rawValue
    }

    /// Packet-size and protocol-mix counters already derived from the fast path.
    public static let packetShape = DetectorFeatureFamily(rawValue: 1 << 0)
    /// TCP and QUIC control-signal counters already derived from the fast path.
    public static let controlSignals = DetectorFeatureFamily(rawValue: 1 << 1)
    /// Burst-onset and burst-shape counters emitted on completed burst records.
    public static let burstShape = DetectorFeatureFamily(rawValue: 1 << 2)
    /// DNS, TLS, domain, and classifier hints attached directly to sparse records.
    public static let hostHints = DetectorFeatureFamily(rawValue: 1 << 3)
    /// QUIC version, packet type, and connection IDs.
    public static let quicIdentity = DetectorFeatureFamily(rawValue: 1 << 4)
    /// Source and destination address strings decoded lazily for detector reads.
    public static let stringAddresses = DetectorFeatureFamily(rawValue: 1 << 5)
    /// DNS answer address arrays surfaced on metadata records.
    public static let dnsAnswerAddresses = DetectorFeatureFamily(rawValue: 1 << 6)
    /// Best-effort DNS-to-flow association for hostless traffic.
    public static let dnsAssociation = DetectorFeatureFamily(rawValue: 1 << 7)
    /// Reuse and lineage fields that stitch related flows into one long-lived family.
    public static let lineage = DetectorFeatureFamily(rawValue: 1 << 8)
    /// Path-regime fields derived from `NWPathMonitor` snapshots.
    public static let pathRegime = DetectorFeatureFamily(rawValue: 1 << 9)
    /// Fused service-family attribution built from signatures, host hints, and DNS association.
    public static let serviceAttribution = DetectorFeatureFamily(rawValue: 1 << 10)

    /// Compatibility surface matching the package's pre-requirements detector view.
    public static let legacyDetectorSurface: DetectorFeatureFamily = [
        .packetShape,
        .controlSignals,
        .burstShape,
        .hostHints,
        .quicIdentity,
        .stringAddresses,
        .dnsAnswerAddresses
    ]
}

/// Declares which sparse record kinds and enrichment families a detector actually needs.
/// Decision: the worker computes the union once and avoids activating expensive enrichment unless some installed
/// detector explicitly opts into it.
public struct DetectorRequirements: Sendable, Hashable {
    public let recordKinds: Set<PacketSampleKind>
    public let featureFamilies: DetectorFeatureFamily
    public let preferredFlowSliceIntervalMs: Int?

    public init(
        recordKinds: Set<PacketSampleKind>,
        featureFamilies: DetectorFeatureFamily = [],
        preferredFlowSliceIntervalMs: Int? = nil
    ) {
        self.recordKinds = recordKinds
        self.featureFamilies = featureFamilies
        if let preferredFlowSliceIntervalMs, recordKinds.contains(.flowSlice) {
            self.preferredFlowSliceIntervalMs = max(200, min(preferredFlowSliceIntervalMs, 1_000))
        } else {
            self.preferredFlowSliceIntervalMs = nil
        }
    }

    /// Compatibility default used when a detector does not declare requirements explicitly.
    public static let legacyDefault = DetectorRequirements(
        recordKinds: Set(PacketSampleKind.allCases),
        featureFamilies: .legacyDetectorSurface,
        preferredFlowSliceIntervalMs: 250
    )
}

internal struct DetectorRecordProjection: Sendable {
    let recordKinds: Set<PacketSampleKind>
    let featureFamilies: DetectorFeatureFamily

    static let legacyDefault = DetectorRecordProjection(requirements: .legacyDefault)

    init(requirements: DetectorRequirements) {
        self.recordKinds = requirements.recordKinds
        self.featureFamilies = requirements.featureFamilies
    }

    func includes(_ kind: PacketSampleKind) -> Bool {
        recordKinds.contains(kind)
    }

    func includes(_ featureFamily: DetectorFeatureFamily) -> Bool {
        featureFamilies.contains(featureFamily)
    }
}

internal struct DetectorRuntimePlan: Sendable {
    let detectorRequirements: [String: DetectorRequirements]
    let unionRecordKinds: Set<PacketSampleKind>
    let unionFeatureFamilies: DetectorFeatureFamily
    let flowSliceIntervalMs: Int
    let liveTapFeatureFamilies: DetectorFeatureFamily

    init(detectors: [any TrafficDetector], liveTapEnabled: Bool) {
        var requirementsByIdentifier: [String: DetectorRequirements] = [:]
        var unionRecordKinds: Set<PacketSampleKind> = []
        var unionFeatureFamilies: DetectorFeatureFamily = []
        var preferredFlowSliceIntervals: [Int] = []

        for detector in detectors {
            let requirements = detector.requirements
            requirementsByIdentifier[detector.identifier] = requirements
            unionRecordKinds.formUnion(requirements.recordKinds)
            unionFeatureFamilies.formUnion(requirements.featureFamilies)
            if let interval = requirements.preferredFlowSliceIntervalMs {
                preferredFlowSliceIntervals.append(interval)
            }
        }

        if liveTapEnabled {
            unionRecordKinds.formUnion(Self.liveTapRecordKinds)
            unionFeatureFamilies.formUnion(Self.liveTapFeatureFamilies)
        }

        self.detectorRequirements = requirementsByIdentifier
        self.unionRecordKinds = unionRecordKinds
        self.unionFeatureFamilies = unionFeatureFamilies
        self.flowSliceIntervalMs = preferredFlowSliceIntervals.min() ?? 250
        self.liveTapFeatureFamilies = liveTapEnabled ? Self.liveTapFeatureFamilies : []
    }

    private static let liveTapRecordKinds: Set<PacketSampleKind> = [
        .flowOpen,
        .flowClose,
        .metadata,
        .burst,
        .activitySample
    ]

    private static let liveTapFeatureFamilies: DetectorFeatureFamily = [
        .packetShape,
        .controlSignals,
        .burstShape,
        .hostHints,
        .quicIdentity,
        .dnsAnswerAddresses
    ]

    func projection(for detector: any TrafficDetector) -> DetectorRecordProjection {
        DetectorRecordProjection(requirements: detectorRequirements[detector.identifier] ?? .legacyDefault)
    }

    var needsFlowSlices: Bool {
        unionRecordKinds.contains(.flowSlice)
    }

    var needsFlowCloseEvents: Bool {
        unionRecordKinds.contains(.flowClose)
    }

    var needsBurstShapeCounters: Bool {
        unionFeatureFamilies.contains(.burstShape)
    }

    var needsDeepMetadata: Bool {
        unionFeatureFamilies.contains(.hostHints) ||
            unionFeatureFamilies.contains(.dnsAssociation) ||
            unionFeatureFamilies.contains(.serviceAttribution) ||
            unionFeatureFamilies.contains(.dnsAnswerAddresses)
    }

    var needsDNSAssociation: Bool {
        unionFeatureFamilies.contains(.dnsAssociation)
    }

    var needsLineage: Bool {
        unionFeatureFamilies.contains(.lineage)
    }

    var needsPathRegime: Bool {
        unionFeatureFamilies.contains(.pathRegime)
    }

    var needsServiceAttribution: Bool {
        unionFeatureFamilies.contains(.serviceAttribution)
    }

    var needsQUICIdentity: Bool {
        unionFeatureFamilies.contains(.quicIdentity) || needsLineage || needsServiceAttribution
    }

    var needsHostHints: Bool {
        unionFeatureFamilies.contains(.hostHints) || needsDNSAssociation || needsServiceAttribution
    }
}
