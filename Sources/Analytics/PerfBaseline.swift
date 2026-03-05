import Foundation

public enum PerfMetricDirection: String, Codable, Sendable {
    case lowerIsBetter = "lower_is_better"
    case higherIsBetter = "higher_is_better"
}

public struct PerfMetricEntry: Codable, Sendable, Equatable {
    public let name: String
    public let unit: String
    public let direction: PerfMetricDirection
    public let baselineValue: Double

    public enum CodingKeys: String, CodingKey {
        case name
        case unit
        case direction
        case baselineValue = "baseline_value"
    }
}

public struct PerfToleranceEntry: Codable, Sendable, Equatable {
    public let warnPct: Double
    public let failPct: Double
    public let warnAbs: Double?
    public let failAbs: Double?

    public enum CodingKeys: String, CodingKey {
        case warnPct = "warn_pct"
        case failPct = "fail_pct"
        case warnAbs = "warn_abs"
        case failAbs = "fail_abs"
    }
}

public struct PerfScenarioEntry: Codable, Sendable, Equatable {
    public let id: String
    public let durationSeconds: Int
    public let seed: UInt64
    public let inputProfile: String

    public enum CodingKeys: String, CodingKey {
        case id
        case durationSeconds = "duration_seconds"
        case seed
        case inputProfile = "input_profile"
    }
}

/// Immutable baseline contract for local and CI performance gates.
public struct PerfBaseline: Codable, Sendable, Equatable {
    public let baselineName: String
    public let generatedAt: Date
    public let runtimeProfile: String
    public let metrics: [PerfMetricEntry]
    public let tolerances: [String: PerfToleranceEntry]
    public let scenarios: [PerfScenarioEntry]

    public enum CodingKeys: String, CodingKey {
        case baselineName = "baseline_name"
        case generatedAt = "generated_at"
        case runtimeProfile = "runtime_profile"
        case metrics
        case tolerances
        case scenarios
    }

    public static func load(from data: Data) throws -> PerfBaseline {
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601
        return try decoder.decode(PerfBaseline.self, from: data)
    }

    public static func load(from url: URL) throws -> PerfBaseline {
        try load(from: Data(contentsOf: url))
    }
}

public struct PerfEvaluationViolation: Sendable, Equatable {
    public let metricName: String
    public let measuredValue: Double
    public let baselineValue: Double
    public let reason: String
}

public struct PerfEvaluationReport: Sendable, Equatable {
    public let warnings: [PerfEvaluationViolation]
    public let failures: [PerfEvaluationViolation]

    public var hasFailures: Bool {
        !failures.isEmpty
    }
}

public enum PerfBaselineEvaluator {
    public static func evaluate(
        baseline: PerfBaseline,
        measured: [String: Double],
        failMode: Bool
    ) -> PerfEvaluationReport {
        var warnings: [PerfEvaluationViolation] = []
        var failures: [PerfEvaluationViolation] = []

        for metric in baseline.metrics {
            guard let measuredValue = measured[metric.name],
                  let tolerance = baseline.tolerances[metric.name]
            else {
                continue
            }

            let regression = worseAmount(metric: metric, measuredValue: measuredValue)
            let regressionPct = metric.baselineValue == 0
                ? 0
                : (regression / abs(metric.baselineValue)) * 100

            let failureByPct = regressionPct > tolerance.failPct
            let warningByPct = regressionPct > tolerance.warnPct
            let failureByAbs = tolerance.failAbs.map { regression > $0 } ?? false
            let warningByAbs = tolerance.warnAbs.map { regression > $0 } ?? false

            if failMode && (failureByPct || failureByAbs) {
                failures.append(
                    PerfEvaluationViolation(
                        metricName: metric.name,
                        measuredValue: measuredValue,
                        baselineValue: metric.baselineValue,
                        reason: "Exceeded fail tolerance"
                    )
                )
                continue
            }

            if warningByPct || warningByAbs {
                warnings.append(
                    PerfEvaluationViolation(
                        metricName: metric.name,
                        measuredValue: measuredValue,
                        baselineValue: metric.baselineValue,
                        reason: "Exceeded warning tolerance"
                    )
                )
            }
        }

        return PerfEvaluationReport(warnings: warnings, failures: failures)
    }

    private static func worseAmount(metric: PerfMetricEntry, measuredValue: Double) -> Double {
        switch metric.direction {
        case .lowerIsBetter:
            return max(0, measuredValue - metric.baselineValue)
        case .higherIsBetter:
            return max(0, metric.baselineValue - measuredValue)
        }
    }
}
