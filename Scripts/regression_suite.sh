#!/usr/bin/env bash

set -euo pipefail

TEST_USER=${TEST_USER:-rpclient}
HARNESS_LOG=${HARNESS_LOG:-/root/runner.log}
HTTP_RETRIES=${HTTP_RETRIES:-2}

if [[ $EUID -ne 0 ]]; then
  echo "Run this script as root so it can switch users and inspect harness logs." >&2
  exit 1
fi

if ! id -u "$TEST_USER" >/dev/null 2>&1; then
  echo "Test user '$TEST_USER' does not exist. Create it or export TEST_USER." >&2
  exit 1
fi

log_section() {
  echo "==== $1 ===="
}

log_section "IPv4/IPv6 HTTP probes"
HTTP_TARGETS=(
  "https://example.com"
  "http://neverssl.com"
  "https://www.rust-lang.org"
)
for target in "${HTTP_TARGETS[@]}"; do
  echo "==> HEAD $target"
  curl_opts=(-I --max-time 20)
  if [[ "$target" == http://neverssl.com* ]]; then
    curl_opts=(-4 "${curl_opts[@]}")
  fi
  attempt=1
  until runuser -u "$TEST_USER" -- curl "${curl_opts[@]}" "$target"; do
    if (( attempt >= HTTP_RETRIES )); then
      echo "HTTP probe failed for $target" >&2
      exit 1
    fi
    echo "HTTP probe retry $attempt for $target"
    attempt=$((attempt + 1))
    sleep 1
  done
done

log_section "HTTP/3 QUIC probe"
if runuser -u "$TEST_USER" -- curl --version | grep -qi "HTTP3"; then
  TEST_USER="$TEST_USER" bash "$(dirname "$0")/quic_probe.sh" https://cloudflare-quic.com
else
  echo "[skip] curl for $TEST_USER lacks HTTP/3 support"
fi

log_section "DNS resolver tests"
echo "==> IPv4 resolver (1.1.1.1)"
if ! runuser -u "$TEST_USER" -- dig example.com @1.1.1.1 +time=2 +tries=1 +noshort; then
  echo "IPv4 dig failed" >&2
  exit 1
fi
echo
echo "==> IPv6 resolver (2606:4700:4700::1111)"
if ! runuser -u "$TEST_USER" -- dig example.com @2606:4700:4700::1111 AAAA +time=2 +tries=1 +noshort; then
  echo "[fallback] system resolver answers for example.com:"
  runuser -u "$TEST_USER" -- getent ahosts example.com | awk '{print "  "$1}'
fi

log_section "Harness log inspection"
if [[ -f "$HARNESS_LOG" ]]; then
  if grep -E "FlowManager: warn|failed to" "$HARNESS_LOG"; then
    echo "Warnings detected in harness log." >&2
    exit 1
  else
    tail -n 20 "$HARNESS_LOG"
  fi
else
  echo "Harness log $HARNESS_LOG not found." >&2
  exit 1
fi

echo "Regression suite completed."
