#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

FIRST_PARTY_PATH_REGEX='(Sources/(TunnelControl|TunnelRuntime|DataplaneFFI|PacketRelay|Analytics|Observability|HostClient|HarnessLocal)|Tests/(DataplaneFFITests|TunnelRuntimeTests|AnalyticsTests|ObservabilityTests|PacketRelayTests|HarnessLocalTests))'
PERF_BASELINE_PATH="${PERF_BASELINE_PATH:-Config/PerfBaseline.json}"
PERF_MEASUREMENTS_PATH="${PERF_MEASUREMENTS_PATH:-}"
PERF_FAIL_MODE="${PERF_FAIL_MODE:-0}"

check_first_party_warnings() {
  local log_file="$1"
  local stage="$2"

  local matches
  matches="$(grep -E "warning:" "$log_file" | grep -E "$FIRST_PARTY_PATH_REGEX" || true)"
  if [[ -n "$matches" ]]; then
    echo "First-party warnings detected during ${stage}:" >&2
    echo "$matches" >&2
    exit 1
  fi
}

run_stage() {
  local stage="$1"
  shift
  local log_file
  log_file="$(mktemp)"

  echo "==> ${stage}"
  if ! "$@" 2>&1 | tee "$log_file"; then
    echo "${stage} failed" >&2
    exit 1
  fi

  check_first_party_warnings "$log_file" "$stage"
}

run_perf_check() {
  if [[ -z "$PERF_MEASUREMENTS_PATH" ]]; then
    echo "==> perf baseline check skipped (PERF_MEASUREMENTS_PATH not set)"
    return
  fi

  if [[ ! -f "$PERF_MEASUREMENTS_PATH" ]]; then
    echo "PERF_MEASUREMENTS_PATH does not exist: $PERF_MEASUREMENTS_PATH" >&2
    exit 1
  fi

  if [[ ! -f "$PERF_BASELINE_PATH" ]]; then
    echo "PERF_BASELINE_PATH does not exist: $PERF_BASELINE_PATH" >&2
    exit 1
  fi

  echo "==> perf baseline evaluation"
  swift -e '
import Foundation

struct Metric: Decodable {
    let name: String
    let direction: String
    let baselineValue: Double

    enum CodingKeys: String, CodingKey {
        case name
        case direction
        case baselineValue = "baseline_value"
    }
}

struct Tolerance: Decodable {
    let warnPct: Double
    let failPct: Double
    let warnAbs: Double?
    let failAbs: Double?

    enum CodingKeys: String, CodingKey {
        case warnPct = "warn_pct"
        case failPct = "fail_pct"
        case warnAbs = "warn_abs"
        case failAbs = "fail_abs"
    }
}

struct Baseline: Decodable {
    let metrics: [Metric]
    let tolerances: [String: Tolerance]
}

let baselinePath = CommandLine.arguments[1]
let measuredPath = CommandLine.arguments[2]
let failMode = CommandLine.arguments[3] == "1"
let baselineData = try Data(contentsOf: URL(fileURLWithPath: baselinePath))
let measuredData = try Data(contentsOf: URL(fileURLWithPath: measuredPath))
let baseline = try JSONDecoder().decode(Baseline.self, from: baselineData)
let measured = try JSONDecoder().decode([String: Double].self, from: measuredData)

var warnings: [String] = []
var failures: [String] = []

for metric in baseline.metrics {
    guard let measuredValue = measured[metric.name], let tolerance = baseline.tolerances[metric.name] else {
        continue
    }

    let regression: Double
    if metric.direction == "lower_is_better" {
        regression = max(0, measuredValue - metric.baselineValue)
    } else {
        regression = max(0, metric.baselineValue - measuredValue)
    }

    let pct = metric.baselineValue == 0 ? 0 : (regression / abs(metric.baselineValue)) * 100
    let failByPct = pct > tolerance.failPct
    let warnByPct = pct > tolerance.warnPct
    let failByAbs = tolerance.failAbs.map { regression > $0 } ?? false
    let warnByAbs = tolerance.warnAbs.map { regression > $0 } ?? false

    if failMode && (failByPct || failByAbs) {
        failures.append(metric.name)
    } else if warnByPct || warnByAbs {
        warnings.append(metric.name)
    }
}

if !warnings.isEmpty {
    fputs("Perf warnings: \(warnings.joined(separator: ", "))\n", stderr)
}

if !failures.isEmpty {
    fputs("Perf failures: \(failures.joined(separator: ", "))\n", stderr)
    exit(1)
}
' "$PERF_BASELINE_PATH" "$PERF_MEASUREMENTS_PATH" "$PERF_FAIL_MODE"
}

run_stage "swift build" swift build
run_stage "swift test" swift test
run_perf_check

echo "quality-gate: PASS"
