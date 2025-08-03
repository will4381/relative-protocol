#!/bin/bash

set -euo pipefail

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BUILD_DIR="${PROJECT_ROOT}/build"
INSTALL_DIR="${PROJECT_ROOT}/install"

print_usage() {
    echo "Usage: $0 [options]"
    echo "Options:"
    echo "  -d, --debug     Build in debug mode (default: release)"
    echo "  -t, --tests     Enable tests"
    echo "  -f, --fuzzing   Enable fuzzing"
    echo "  -a, --asan      Enable AddressSanitizer"
    echo "  -l, --logging   Enable debug logging"
    echo "  -x, --xcframework Build XCFramework"
    echo "  -c, --clean     Clean build directory first"
    echo "  -h, --help      Show this help message"
}

BUILD_TYPE="Release"
ENABLE_TESTS="OFF"
ENABLE_FUZZING="OFF"
ENABLE_ASAN="OFF"
ENABLE_LOGGING="OFF"
BUILD_XCFRAMEWORK="OFF"
CLEAN_BUILD=false

while [[ $# -gt 0 ]]; do
    case $1 in
        -d|--debug)
            BUILD_TYPE="Debug"
            shift
            ;;
        -t|--tests)
            ENABLE_TESTS="ON"
            shift
            ;;
        -f|--fuzzing)
            ENABLE_FUZZING="ON"
            BUILD_TYPE="Debug"
            shift
            ;;
        -a|--asan)
            ENABLE_ASAN="ON"
            BUILD_TYPE="Debug"
            shift
            ;;
        -l|--logging)
            ENABLE_LOGGING="ON"
            shift
            ;;
        -x|--xcframework)
            BUILD_XCFRAMEWORK="ON"
            shift
            ;;
        -c|--clean)
            CLEAN_BUILD=true
            shift
            ;;
        -h|--help)
            print_usage
            exit 0
            ;;
        *)
            echo "Unknown option: $1"
            print_usage
            exit 1
            ;;
    esac
done

if [[ "$CLEAN_BUILD" == true ]]; then
    echo "Cleaning build directory..."
    rm -rf "$BUILD_DIR"
fi

mkdir -p "$BUILD_DIR"
mkdir -p "$INSTALL_DIR"

echo "Building RelativeVPN for iOS..."
echo "Build type: $BUILD_TYPE"
echo "Tests: $ENABLE_TESTS"
echo "Fuzzing: $ENABLE_FUZZING"
echo "ASan: $ENABLE_ASAN"
echo "Logging: $ENABLE_LOGGING"
echo "XCFramework: $BUILD_XCFRAMEWORK"

cd "$BUILD_DIR"

cmake \
    -DCMAKE_SYSTEM_NAME=iOS \
    -DCMAKE_OSX_DEPLOYMENT_TARGET=12.0 \
    -DCMAKE_OSX_ARCHITECTURES="arm64;x86_64" \
    -DCMAKE_BUILD_TYPE="$BUILD_TYPE" \
    -DCMAKE_INSTALL_PREFIX="$INSTALL_DIR" \
    -DENABLE_TESTS="$ENABLE_TESTS" \
    -DENABLE_FUZZING="$ENABLE_FUZZING" \
    -DENABLE_ASAN="$ENABLE_ASAN" \
    -DENABLE_LOGGING="$ENABLE_LOGGING" \
    -DBUILD_XCFRAMEWORK="$BUILD_XCFRAMEWORK" \
    -DBUILD_STATIC=ON \
    "$PROJECT_ROOT"

cmake --build . --config "$BUILD_TYPE" --parallel $(sysctl -n hw.ncpu)

if [[ "$ENABLE_TESTS" == "ON" ]]; then
    echo "Running tests..."
    ctest --output-on-failure --parallel $(sysctl -n hw.ncpu)
fi

cmake --install . --config "$BUILD_TYPE"

if [[ "$BUILD_XCFRAMEWORK" == "ON" ]]; then
    echo "Building XCFramework..."
    cmake --build . --target xcframework
fi

echo "Build completed successfully!"
echo "Install directory: $INSTALL_DIR"
if [[ "$BUILD_XCFRAMEWORK" == "ON" ]]; then
    echo "XCFramework: $BUILD_DIR/RelativeVPN.xcframework"
fi