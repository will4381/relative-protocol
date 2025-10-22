#!/bin/bash
# Builds the gomobile-based Tun2Socks.xcframework for iOS + macOS.

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUTPUT_DIR="${ROOT_DIR}/Build/Tun2Socks"
MODULE_NAME="Tun2Socks"
LOCAL_GOPATH="${ROOT_DIR}/Build/.gopath"
LOCAL_GOMOBILE_CACHE="${ROOT_DIR}/Build/.gomobile"
PACKAGE_BINARY_DIR="${ROOT_DIR}/RelativeProtocol/Binary"

DEFAULT_GOPATH="$(go env GOPATH 2>/dev/null || true)"

if command -v gomobile >/dev/null 2>&1; then
  GOMOBILE_BIN="$(command -v gomobile)"
elif [[ -n "${DEFAULT_GOPATH}" && -x "${DEFAULT_GOPATH}/bin/gomobile" ]]; then
  GOMOBILE_BIN="${DEFAULT_GOPATH}/bin/gomobile"
else
  echo "gomobile is not installed. Install via 'go install golang.org/x/mobile/cmd/gomobile@latest'." >&2
  exit 1
fi

mkdir -p "${OUTPUT_DIR}"
mkdir -p "${LOCAL_GOPATH}"
mkdir -p "${LOCAL_GOMOBILE_CACHE}"

export GOPATH="${LOCAL_GOPATH}"
export GOMOBILECACHE="${LOCAL_GOMOBILE_CACHE}"
export GOMODCACHE="${LOCAL_GOPATH}/pkg/mod"

pushd "${ROOT_DIR}/ThirdParty/tun2socks" >/dev/null

echo "Skipping go mod tidy to preserve tool dependencies..."

echo "Initializing gomobile..."
"${GOMOBILE_BIN}" init

echo "Producing xcframework output in ${OUTPUT_DIR}..."
mkdir -p "${OUTPUT_DIR}"

"${GOMOBILE_BIN}" bind \
  -target=ios,macos \
  -o "${OUTPUT_DIR}/${MODULE_NAME}.xcframework" \
  ./bridge

popd >/dev/null

echo "Framework generated at ${OUTPUT_DIR}/${MODULE_NAME}.xcframework"

echo "Syncing xcframework into package binary directory..."
mkdir -p "${PACKAGE_BINARY_DIR}"
rsync -a --delete "${OUTPUT_DIR}/${MODULE_NAME}.xcframework" "${PACKAGE_BINARY_DIR}/"
echo "Updated ${PACKAGE_BINARY_DIR}/${MODULE_NAME}.xcframework"
