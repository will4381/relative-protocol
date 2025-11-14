#!/usr/bin/env bash

set -euo pipefail

TEST_USER=${TEST_USER:-rpclient}
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

require_user() {
    if ! id -u "$TEST_USER" >/dev/null 2>&1; then
        echo "Test user '$TEST_USER' does not exist. Create it or export TEST_USER." >&2
        exit 1
    fi
}

run_as_user() {
    runuser -u "$TEST_USER" -- "$@"
}

section() {
    echo "==== $1 ===="
}

require_user

section "Standard HTTP/HTTPS sweep"
HTTP_TARGETS=(
    "https://example.com"
    "http://neverssl.com"
    "https://www.rust-lang.org"
)
for target in "${HTTP_TARGETS[@]}"; do
    echo "==> HEAD $target"
    run_as_user curl -I --max-time 20 "$target"
done

section "HTTP POST payload"
run_as_user curl -X POST https://httpbin.org/post \
    -H 'Content-Type: application/json' \
    -d '{"message":"hello from traffic_matrix"}' \
    --max-time 15

section "Large download (5 MB)"
run_as_user curl -L 'https://speed.cloudflare.com/__down?bytes=5000000' \
    --output /dev/null --max-time 30

section "Concurrent burst (5 parallel GETs)"
printf "%s\n" https://example.com https://www.rust-lang.org \
    https://icanhazip.com https://ifconfig.co/json https://neverssl.com |
    xargs -I {} -P 5 runuser -u "$TEST_USER" -- curl -s -o /dev/null --max-time 15 {}

section "HTTP/3 QUIC check"
TEST_USER="$TEST_USER" bash "$SCRIPT_DIR/quic_probe.sh" https://cloudflare-quic.com || true

echo "Traffic matrix complete."
