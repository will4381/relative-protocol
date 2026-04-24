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

if [[ -n "${VPN_BRIDGE_IOS_PROJECT:-}" && -n "${VPN_BRIDGE_IOS_SCHEME:-}" ]]; then
  run_stage "iOS extension smoke build" Scripts/ios-extension-smoke.sh
else
  echo "==> iOS extension smoke build skipped (set VPN_BRIDGE_IOS_PROJECT and VPN_BRIDGE_IOS_SCHEME)"
fi

echo "quality-gate: PASS"
