#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

FIRST_PARTY_PATH_REGEX='(Sources/(TunnelControl|TunnelRuntime|DataplaneFFI|PacketRelay|Analytics|Observability|HostClient|HarnessLocal)|Tests/(DataplaneFFITests|TunnelRuntimeTests|AnalyticsTests|ObservabilityTests|PacketRelayTests|HarnessLocalTests))'

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

run_stage "swift build" swift build
run_stage "swift test" swift test

run_stage "perf baseline validation" python3 - "$ROOT_DIR/Config/PerfBaseline.json" "${VPN_BRIDGE_PERF_RESULTS:-}" <<'PY'
import json
import sys

baseline_path = sys.argv[1]
results_path = sys.argv[2]

with open(baseline_path, "r", encoding="utf-8") as handle:
    baseline = json.load(handle)

metrics = baseline.get("metrics")
tolerances = baseline.get("tolerances")
if not isinstance(metrics, list) or not metrics:
    raise SystemExit("Perf baseline must contain a non-empty metrics list")
if not isinstance(tolerances, dict):
    raise SystemExit("Perf baseline must contain a tolerances object")

baseline_by_name = {}
for metric in metrics:
    name = metric.get("name")
    direction = metric.get("direction")
    value = metric.get("baseline_value")
    if not name or direction not in {"lower_is_better", "higher_is_better"}:
        raise SystemExit(f"Invalid perf metric entry: {metric!r}")
    if not isinstance(value, (int, float)):
        raise SystemExit(f"Perf metric {name} is missing numeric baseline_value")
    if name not in tolerances:
        raise SystemExit(f"Perf metric {name} is missing tolerances")
    baseline_by_name[name] = metric

if not results_path:
    print("perf baseline: schema valid; comparison skipped (set VPN_BRIDGE_PERF_RESULTS)")
    raise SystemExit(0)

with open(results_path, "r", encoding="utf-8") as handle:
    results = json.load(handle)

raw_results = results.get("metrics", results)
if isinstance(raw_results, list):
    result_by_name = {item.get("name"): item.get("value") for item in raw_results}
elif isinstance(raw_results, dict):
    result_by_name = raw_results
else:
    raise SystemExit("Perf results must be a metrics list or name/value object")

failures = []
warnings = []
for name, metric in baseline_by_name.items():
    actual = result_by_name.get(name)
    if not isinstance(actual, (int, float)):
        failures.append(f"{name}: missing numeric result")
        continue

    expected = float(metric["baseline_value"])
    tolerance = tolerances[name]
    warn_delta = max(float(tolerance.get("warn_abs", 0)), expected * float(tolerance.get("warn_pct", 0)) / 100.0)
    fail_delta = max(float(tolerance.get("fail_abs", 0)), expected * float(tolerance.get("fail_pct", 0)) / 100.0)

    if metric["direction"] == "lower_is_better":
        warn_threshold = expected + warn_delta
        fail_threshold = expected + fail_delta
        if actual > fail_threshold:
            failures.append(f"{name}: {actual} > fail threshold {fail_threshold}")
        elif actual > warn_threshold:
            warnings.append(f"{name}: {actual} > warn threshold {warn_threshold}")
    else:
        warn_threshold = expected - warn_delta
        fail_threshold = expected - fail_delta
        if actual < fail_threshold:
            failures.append(f"{name}: {actual} < fail threshold {fail_threshold}")
        elif actual < warn_threshold:
            warnings.append(f"{name}: {actual} < warn threshold {warn_threshold}")

for warning in warnings:
    print(f"perf baseline warning: {warning}", file=sys.stderr)
if failures:
    for failure in failures:
        print(f"perf baseline failure: {failure}", file=sys.stderr)
    raise SystemExit(1)

print("perf baseline: PASS")
PY

if [[ -n "${VPN_BRIDGE_IOS_PROJECT:-}" && -n "${VPN_BRIDGE_IOS_SCHEME:-}" ]]; then
  run_stage "iOS extension smoke build" Scripts/ios-extension-smoke.sh
else
  echo "==> iOS extension smoke build skipped (set VPN_BRIDGE_IOS_PROJECT and VPN_BRIDGE_IOS_SCHEME)"
fi

echo "quality-gate: PASS"
