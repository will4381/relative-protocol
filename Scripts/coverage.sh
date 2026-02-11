#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

BUILD_DIR="${BUILD_DIR:-.build}"
REPORT_DIR="${REPORT_DIR:-$BUILD_DIR/coverage}"
SCHEME_TEST_BINARY=""
RUN_TESTS="${RUN_TESTS:-0}"

mkdir -p "$REPORT_DIR"

if [[ "$RUN_TESTS" == "1" ]]; then
  swift test --enable-code-coverage
fi

# Locate profdata emitted by SwiftPM.
PROFDATA_PATH="$(find "$BUILD_DIR" -type f -name default.profdata | head -n 1 || true)"
if [[ -z "$PROFDATA_PATH" ]]; then
  swift test --enable-code-coverage
  PROFDATA_PATH="$(find "$BUILD_DIR" -type f -name default.profdata | head -n 1 || true)"
  if [[ -z "$PROFDATA_PATH" ]]; then
    echo "error: unable to locate default.profdata under $BUILD_DIR" >&2
    exit 1
  fi
fi

# Locate the package test binary (works across macOS layouts).
# Prefer Darwin .xctest executables, then Linux/other.
mapfile -t CANDIDATES < <(
  {
    find "$BUILD_DIR" -type f -path "*.xctest/Contents/MacOS/*" ! -path "*.dSYM/*" 2>/dev/null
    find "$BUILD_DIR" -type f -name "*PackageTests" 2>/dev/null
  } | awk '!seen[$0]++'
)

for candidate in "${CANDIDATES[@]}"; do
  if xcrun llvm-cov report "$candidate" -instr-profile "$PROFDATA_PATH" >/dev/null 2>&1; then
    SCHEME_TEST_BINARY="$candidate"
    break
  fi
done

if [[ -z "$SCHEME_TEST_BINARY" ]]; then
  echo "error: unable to find a test binary with coverage data under $BUILD_DIR" >&2
  exit 1
fi

TEXT_REPORT="$REPORT_DIR/coverage.txt"
JSON_REPORT="$REPORT_DIR/coverage.json"
SOURCE_SUMMARY="$REPORT_DIR/source_summary.txt"

xcrun llvm-cov report \
  "$SCHEME_TEST_BINARY" \
  -instr-profile "$PROFDATA_PATH" \
  > "$TEXT_REPORT"

xcrun llvm-cov export \
  "$SCHEME_TEST_BINARY" \
  -instr-profile "$PROFDATA_PATH" \
  -format=text \
  > "$JSON_REPORT"

{
  echo "Source coverage totals"
  awk '$1 ~ /^RelativeProtocol\/Sources\// {r+=$2; mr+=$3; f+=$5; mf+=$6; l+=$8; ml+=$9} END {printf("all_sources lines=%d missed=%d line_cov=%.2f%% regions=%d missed_regions=%d region_cov=%.2f%% functions=%d missed_functions=%d function_cov=%.2f%%\n", l, ml, (l?100*(l-ml)/l:0), r, mr, (r?100*(r-mr)/r:0), f, mf, (f?100*(f-mf)/f:0))}' "$TEXT_REPORT"
  awk '$1 ~ /^RelativeProtocol\/Sources\/RelativeProtocolCore\// {r+=$2; mr+=$3; f+=$5; mf+=$6; l+=$8; ml+=$9} END {printf("core lines=%d missed=%d line_cov=%.2f%% regions=%d missed_regions=%d region_cov=%.2f%% functions=%d missed_functions=%d function_cov=%.2f%%\n", l, ml, (l?100*(l-ml)/l:0), r, mr, (r?100*(r-mr)/r:0), f, mf, (f?100*(f-mf)/f:0))}' "$TEXT_REPORT"
  awk '$1 ~ /^RelativeProtocol\/Sources\/RelativeProtocolTunnel\// {r+=$2; mr+=$3; f+=$5; mf+=$6; l+=$8; ml+=$9} END {printf("tunnel lines=%d missed=%d line_cov=%.2f%% regions=%d missed_regions=%d region_cov=%.2f%% functions=%d missed_functions=%d function_cov=%.2f%%\n", l, ml, (l?100*(l-ml)/l:0), r, mr, (r?100*(r-mr)/r:0), f, mf, (f?100*(f-mf)/f:0))}' "$TEXT_REPORT"
  echo
  echo "Lowest line coverage source files"
  awk '$1 ~ /^RelativeProtocol\/Sources\// {lines=$8; missed=$9; cov=(lines?100*(lines-missed)/lines:0); printf("%.2f%%\t%s\t(lines:%d missed:%d)\n", cov, $1, lines, missed)}' "$TEXT_REPORT" | sort -n | head -n 10
} > "$SOURCE_SUMMARY"

TOTAL_LINE="$(awk '/^TOTAL/{line=$0} END{print line}' "$TEXT_REPORT")"

echo "Coverage report written to: $TEXT_REPORT"
echo "Coverage JSON written to:   $JSON_REPORT"
echo "Source summary written to:  $SOURCE_SUMMARY"
if [[ -n "$TOTAL_LINE" ]]; then
  echo "$TOTAL_LINE"
fi
