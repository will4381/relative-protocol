#!/usr/bin/env bash

set -euo pipefail

TEST_USER=${TEST_USER:-rpclient}
TARGET=${1:-https://cloudflare-quic.com}

if ! id -u "$TEST_USER" >/dev/null 2>&1; then
  echo "Test user '$TEST_USER' does not exist. Create it or export TEST_USER." >&2
  exit 1
fi

run_http3_curl() {
  echo "==> HTTP/3 probe (curl) $TARGET"
  runuser -u "$TEST_USER" -- curl --http3-only -sS -o /dev/null -w "Status: %{http_code}\n" --max-time 20 "$TARGET"
}

ensure_aioquic() {
  if ! runuser -u "$TEST_USER" -- python3 -m pip --version >/dev/null 2>&1; then
    echo "python3-pip missing for $TEST_USER"; return 1
  fi
  if ! runuser -u "$TEST_USER" -- python3 -m pip show aioquic >/dev/null 2>&1; then
    echo "[install] aioquic for $TEST_USER"
    runuser -u "$TEST_USER" -- python3 -m pip install --user --break-system-packages aioquic >/dev/null
  fi
}

run_http3_aioquic() {
  echo "==> HTTP/3 probe (aioquic) $TARGET"
  local helper="/tmp/http3_client.py"
  install -m 755 "$(dirname "$0")/http3_client.py" "$helper"
  runuser -u "$TEST_USER" -- python3 "$helper" "$TARGET"
}

if runuser -u "$TEST_USER" -- curl --version | grep -qi "HTTP3"; then
  if run_http3_curl; then
    exit 0
  else
    echo "curl HTTP/3 probe failed, falling back to aioquic"
  fi
fi

if ensure_aioquic && run_http3_aioquic; then
  exit 0
fi

echo "QUIC probe failed (curl/aioquic unavailable or errored)." >&2
exit 1
