#!/bin/bash
# Builds the Leaf XCFramework for iOS (device + simulator) from a pinned revision.

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUTPUT_DIR="${ROOT_DIR}/Build/Leaf"
PACKAGE_BINARY_DIR="${ROOT_DIR}/RelativeProtocol/Binary"
LEAF_REVISION="${LEAF_REVISION:-d7642868da45ed15e02585281a81c308e2d91ea9}"
LEAF_REPO="https://github.com/eycorsican/leaf.git"
LEAF_SRC_DIR="${ROOT_DIR}/Build/leaf-src"
MODULE_NAME="Leaf"
FRAMEWORK_NAME="${MODULE_NAME}.xcframework"

command -v rustup >/dev/null 2>&1 || {
  echo "rustup is required. Install via https://rustup.rs/." >&2
  exit 1
}

RUST_TOOLCHAIN="${RUST_TOOLCHAIN:-stable}"

if ! command -v rustup >/dev/null 2>&1; then
  echo "rustup is required to build Leaf. Install via https://rustup.rs/." >&2
  exit 1
fi

if ! rustup toolchain list | grep -q "${RUST_TOOLCHAIN}"; then
  rustup toolchain install "${RUST_TOOLCHAIN}"
fi

CARGO_CMD=(rustup run "${RUST_TOOLCHAIN}" cargo)

if ! command -v cbindgen >/dev/null 2>&1; then
  echo "Installing cbindgen..."
  "${CARGO_CMD[@]}" install --force cbindgen
fi

mkdir -p "${OUTPUT_DIR}" "${PACKAGE_BINARY_DIR}"

rm -rf "${LEAF_SRC_DIR}"
git clone --recurse-submodules "${LEAF_REPO}" "${LEAF_SRC_DIR}"
pushd "${LEAF_SRC_DIR}" >/dev/null
git fetch origin --tags
git checkout "${LEAF_REVISION}"
git submodule update --init --recursive

PATCH_DIR="${ROOT_DIR}/ThirdParty/leaf/patches"
if [ -d "${PATCH_DIR}" ]; then
  for patch in "${PATCH_DIR}"/*.patch; do
    [ -f "${patch}" ] || continue
    git apply "${patch}"
  done
fi
popd >/dev/null

export IPHONEOS_DEPLOYMENT_TARGET=13.0

TARGETS=(
  "aarch64-apple-ios"
  "x86_64-apple-ios"
  "aarch64-apple-ios-sim"
)

for target in "${TARGETS[@]}"; do
  rustup target add --toolchain "${RUST_TOOLCHAIN}" "${target}"
done

BUILD_MODE="release"
BUILD_FLAG="--release"

pushd "${LEAF_SRC_DIR}" >/dev/null

"${CARGO_CMD[@]}" build -p leaf-ffi ${BUILD_FLAG} --no-default-features --features "default-ring outbound-quic" --target aarch64-apple-ios
"${CARGO_CMD[@]}" build -p leaf-ffi ${BUILD_FLAG} --no-default-features --features "default-ring outbound-quic" --target x86_64-apple-ios
"${CARGO_CMD[@]}" build -p leaf-ffi ${BUILD_FLAG} --no-default-features --features "default-ring outbound-quic" --target aarch64-apple-ios-sim
"${CARGO_CMD[@]}" build -p leaf-ffi ${BUILD_FLAG} --no-default-features --features "default-aws-lc outbound-quic" --target aarch64-apple-darwin
"${CARGO_CMD[@]}" build -p leaf-ffi ${BUILD_FLAG} --no-default-features --features "default-aws-lc outbound-quic" --target x86_64-apple-darwin

HEADER_DIR="${OUTPUT_DIR}/include"
IOS_DIR="${OUTPUT_DIR}/ios"
SIM_DIR="${OUTPUT_DIR}/ios-sim"
MAC_DIR="${OUTPUT_DIR}/macos"

rm -rf "${HEADER_DIR}" "${IOS_DIR}" "${SIM_DIR}" "${MAC_DIR}"
mkdir -p "${HEADER_DIR}" "${IOS_DIR}" "${SIM_DIR}" "${MAC_DIR}"

cp "target/aarch64-apple-ios/${BUILD_MODE}/libleaf.a" "${IOS_DIR}/libleaf.a"

lipo -create \
  -arch x86_64 "target/x86_64-apple-ios/${BUILD_MODE}/libleaf.a" \
  -arch arm64 "target/aarch64-apple-ios-sim/${BUILD_MODE}/libleaf.a" \
  -output "${SIM_DIR}/libleaf.a"

lipo -create \
  -arch x86_64 "target/x86_64-apple-darwin/${BUILD_MODE}/libleaf.a" \
  -arch arm64 "target/aarch64-apple-darwin/${BUILD_MODE}/libleaf.a" \
  -output "${MAC_DIR}/libleaf.a"

cbindgen --config leaf-ffi/cbindgen.toml leaf-ffi/src/lib.rs > "${HEADER_DIR}/leaf.h"

cat << EOF > "${HEADER_DIR}/module.modulemap"
module Leaf {
    header "leaf.h"
    export *
}
EOF

rm -rf "${OUTPUT_DIR}/${FRAMEWORK_NAME}"

xcodebuild -create-xcframework \
  -library "${IOS_DIR}/libleaf.a" -headers "${HEADER_DIR}" \
  -library "${SIM_DIR}/libleaf.a" -headers "${HEADER_DIR}" \
  -library "${MAC_DIR}/libleaf.a" -headers "${HEADER_DIR}" \
  -output "${OUTPUT_DIR}/${FRAMEWORK_NAME}"

popd >/dev/null

mkdir -p "${PACKAGE_BINARY_DIR}/${FRAMEWORK_NAME}"
rsync -a --delete "${OUTPUT_DIR}/${FRAMEWORK_NAME}/" "${PACKAGE_BINARY_DIR}/${FRAMEWORK_NAME}/"

echo "Leaf XCFramework built at ${PACKAGE_BINARY_DIR}/${FRAMEWORK_NAME}"
