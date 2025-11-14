#!/usr/bin/env bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
ENGINE_DIR="$REPO_ROOT/RelativeProtocol/RustSources/engine-bridge"
OUTPUT_DIR="$REPO_ROOT/RelativeProtocol/Binary"
XCFRAMEWORK_PATH="$OUTPUT_DIR/Engine.xcframework"

TARGETS=(
  "aarch64-apple-ios"
  "aarch64-apple-ios-sim"
  "x86_64-apple-ios"
  "x86_64-apple-darwin"
  "aarch64-apple-darwin"
)

info() {
    printf "[engine-build] %s\n" "$*"
}

ensure_tools() {
    command -v cargo >/dev/null || { echo "cargo is required"; exit 1; }
    command -v rustup >/dev/null || { echo "rustup is required"; exit 1; }
    command -v xcodebuild >/dev/null || { echo "xcodebuild is required"; exit 1; }
}

ensure_targets() {
    for target in "${TARGETS[@]}"; do
        info "adding rustup target ${target}"
        rustup target add "${target}" >/dev/null 2>&1 || true
    done
}

build_target() {
    local target="$1"
    info "building ${target}"
    cargo build \
        --manifest-path "$ENGINE_DIR/Cargo.toml" \
        --lib \
        --release \
        --target "${target}"
}

generate_header() {
    info "generating C header via cbindgen"
    cargo build \
        --manifest-path "$ENGINE_DIR/Cargo.toml" \
        --release \
        --features generate-header
}

create_xcframework() {
    mkdir -p "$OUTPUT_DIR"
    rm -rf "$XCFRAMEWORK_PATH"

    local ios_device="$ENGINE_DIR/target/aarch64-apple-ios/release/libengine_bridge.a"
    local ios_sim_arm="$ENGINE_DIR/target/aarch64-apple-ios-sim/release/libengine_bridge.a"
    local ios_sim_x86="$ENGINE_DIR/target/x86_64-apple-ios/release/libengine_bridge.a"
    local mac_x86="$ENGINE_DIR/target/x86_64-apple-darwin/release/libengine_bridge.a"
    local mac_arm="$ENGINE_DIR/target/aarch64-apple-darwin/release/libengine_bridge.a"
    local ios_sim_universal="$ENGINE_DIR/target/universal-ios-sim/libengine_bridge.a"
    local mac_universal="$ENGINE_DIR/target/universal-macos/libengine_bridge.a"

    mkdir -p "$(dirname "$ios_sim_universal")" "$(dirname "$mac_universal")"
    info "creating universal ios-sim library"
    lipo -create "$ios_sim_arm" "$ios_sim_x86" -output "$ios_sim_universal"
    info "creating universal macOS library"
    lipo -create "$mac_arm" "$mac_x86" -output "$mac_universal"

    info "creating Engine.xcframework"
    xcodebuild -create-xcframework \
        -library "$ios_device" -headers "$ENGINE_DIR/include" \
        -library "$ios_sim_universal" -headers "$ENGINE_DIR/include" \
        -library "$mac_universal" -headers "$ENGINE_DIR/include" \
        -output "$XCFRAMEWORK_PATH" >/dev/null
    info "xcframework created at $XCFRAMEWORK_PATH"

    install_module_maps
}

install_module_maps() {
    local slices=(
        "$XCFRAMEWORK_PATH/ios-arm64"
        "$XCFRAMEWORK_PATH/ios-arm64_x86_64-simulator"
        "$XCFRAMEWORK_PATH/macos-arm64_x86_64"
    )
    for slice in "${slices[@]}"; do
        info "installing module map for $(basename "$slice")"
        mkdir -p "$slice/Modules"
        cat > "$slice/Modules/module.modulemap" <<'EOF'
module EngineBinary {
  header "bridge.h"
  export *
}
EOF
        mkdir -p "$slice/Headers"
        cat > "$slice/Headers/module.modulemap" <<'EOF'
module EngineBinary {
  header "bridge.h"
  export *
}
EOF
    done
}

main() {
    ensure_tools
    ensure_targets
    generate_header
    for target in "${TARGETS[@]}"; do
        build_target "$target"
    done
    create_xcframework
}

main "$@"
