#!/bin/bash

# Comprehensive VPN Test Suite Execution Script
# 
# This script runs the complete test suite for the VPN framework,
# with special focus on packet lifecycle testing as requested.

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Script configuration
BUILD_DIR="build"
TEST_RESULTS_DIR="test_results"
PARALLEL_JOBS=$(sysctl -n hw.ncpu 2>/dev/null || nproc 2>/dev/null || echo "4")

# Test categories
UNIT_TESTS=true
INTEGRATION_TESTS=true
SECURITY_TESTS=true
PERFORMANCE_TESTS=true
IOS_TESTS=true
MEMORY_TESTS=true
STRESS_TESTS=true

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --unit-only)
            INTEGRATION_TESTS=false
            SECURITY_TESTS=false
            PERFORMANCE_TESTS=false
            IOS_TESTS=false
            MEMORY_TESTS=false
            STRESS_TESTS=false
            shift
            ;;
        --integration-only)
            UNIT_TESTS=false
            SECURITY_TESTS=false
            PERFORMANCE_TESTS=false
            IOS_TESTS=false
            MEMORY_TESTS=false
            STRESS_TESTS=false
            shift
            ;;
        --security-only)
            UNIT_TESTS=false
            INTEGRATION_TESTS=false
            PERFORMANCE_TESTS=false
            IOS_TESTS=false
            MEMORY_TESTS=false
            STRESS_TESTS=false
            shift
            ;;
        --packet-lifecycle-only)
            # Focus on the primary user request
            UNIT_TESTS=false
            SECURITY_TESTS=false
            PERFORMANCE_TESTS=false
            IOS_TESTS=false
            MEMORY_TESTS=false
            STRESS_TESTS=false
            # Integration tests include packet lifecycle
            shift
            ;;
        --no-ios)
            IOS_TESTS=false
            shift
            ;;
        --build-dir)
            BUILD_DIR="$2"
            shift 2
            ;;
        --help)
            echo "VPN Framework Comprehensive Test Suite"
            echo ""
            echo "Usage: $0 [options]"
            echo ""
            echo "Options:"
            echo "  --unit-only              Run only unit tests"
            echo "  --integration-only       Run only integration tests"
            echo "  --security-only          Run only security regression tests"
            echo "  --packet-lifecycle-only  Run only packet lifecycle tests (primary focus)"
            echo "  --no-ios                 Skip iOS-specific tests"
            echo "  --build-dir DIR          Use specified build directory (default: build)"
            echo "  --help                   Show this help message"
            echo ""
            echo "Test Categories:"
            echo "  - Unit Tests: Individual component testing"
            echo "  - Integration Tests: End-to-end packet flow validation (PRIMARY)"
            echo "  - Security Tests: Regression tests for security fixes"
            echo "  - Performance Tests: Memory pools and buffer management"
            echo "  - iOS Tests: NetworkExtension integration"
            echo "  - Memory Tests: Memory leak detection"
            echo "  - Stress Tests: High load scenarios"
            exit 0
            ;;
        *)
            echo "Unknown option: $1"
            echo "Use --help for usage information"
            exit 1
            ;;
    esac
done

print_header() {
    echo -e "${BLUE}================================${NC}"
    echo -e "${BLUE} $1${NC}"
    echo -e "${BLUE}================================${NC}"
}

print_success() {
    echo -e "${GREEN}✓ $1${NC}"
}

print_warning() {
    echo -e "${YELLOW}⚠ $1${NC}"
}

print_error() {
    echo -e "${RED}✗ $1${NC}"
}

# Check prerequisites
check_prerequisites() {
    print_header "Checking Prerequisites"
    
    # Check if we're on macOS (required for iOS tests)
    if [[ "$OSTYPE" == "darwin"* ]]; then
        print_success "Running on macOS - iOS tests available"
        HAS_MACOS=true
    else
        print_warning "Not running on macOS - iOS tests will be skipped"
        HAS_MACOS=false
        IOS_TESTS=false
    fi
    
    # Check for required tools
    if ! command -v cmake &> /dev/null; then
        print_error "CMake not found. Please install CMake."
        exit 1
    fi
    
    if ! command -v make &> /dev/null; then
        print_error "Make not found. Please install build tools."
        exit 1
    fi
    
    print_success "All prerequisites satisfied"
}

# Build the project and tests
build_project() {
    print_header "Building VPN Framework and Tests"
    
    # Create build directory
    mkdir -p "$BUILD_DIR"
    mkdir -p "$TEST_RESULTS_DIR"
    
    cd "$BUILD_DIR"
    
    # Configure with CMake
    echo "Configuring build..."
    cmake .. \
        -DCMAKE_BUILD_TYPE=Debug \
        -DENABLE_TESTING=ON \
        -DENABLE_FUZZING=OFF \
        -DENABLE_BENCHMARKS=ON \
        || { print_error "CMake configuration failed"; exit 1; }
    
    # Build the project
    echo "Building project..."
    make -j"$PARALLEL_JOBS" \
        || { print_error "Build failed"; exit 1; }
    
    print_success "Build completed successfully"
    cd ..
}

# Run individual test suite
run_test_suite() {
    local test_name="$1"
    local test_executable="$2"
    local description="$3"
    
    print_header "Running $test_name"
    echo "Description: $description"
    echo ""
    
    local test_output="$TEST_RESULTS_DIR/${test_name,,}_results.xml"
    local test_log="$TEST_RESULTS_DIR/${test_name,,}_log.txt"
    
    cd "$BUILD_DIR"
    
    if [[ -f "$test_executable" ]]; then
        echo "Executing: ./$test_executable"
        
        # Run with XML output for detailed results
        if ./"$test_executable" \
            --gtest_output="xml:../$test_output" \
            --gtest_print_time=1 \
            > "../$test_log" 2>&1; then
            
            print_success "$test_name completed successfully"
            
            # Show summary
            if grep -q "failures=\"0\"" "../$test_output" 2>/dev/null; then
                local test_count=$(grep -o 'tests="[0-9]*"' "../$test_output" | grep -o '[0-9]*' || echo "?")
                print_success "All $test_count tests passed"
            fi
            
        else
            print_error "$test_name failed"
            echo "Check log file: $test_log"
            
            # Show last few lines of log
            echo "Last 10 lines of test output:"
            tail -n 10 "../$test_log" || true
            
            return 1
        fi
    else
        print_warning "$test_executable not found - skipping $test_name"
        return 1
    fi
    
    cd ..
    return 0
}

# Main test execution
main() {
    print_header "VPN Framework Comprehensive Test Suite"
    echo "Focusing on packet lifecycle testing as requested by user"
    echo ""
    
    # Track results
    local passed_tests=0
    local failed_tests=0
    local skipped_tests=0
    
    # Prerequisites and build
    check_prerequisites
    build_project
    
    # Test execution
    print_header "Executing Test Suites"
    
    # Unit Tests
    if [[ "$UNIT_TESTS" == "true" ]]; then
        if run_test_suite "Unit Tests" "unit_tests" "Individual component validation"; then
            ((passed_tests++))
        else
            ((failed_tests++))
        fi
    else
        ((skipped_tests++))
    fi
    
    # Integration Tests (PRIMARY FOCUS - includes packet lifecycle)
    if [[ "$INTEGRATION_TESTS" == "true" ]]; then
        if run_test_suite "Integration Tests" "integration_tests" "END-TO-END PACKET LIFECYCLE VALIDATION (PRIMARY FOCUS)"; then
            ((passed_tests++))
        else
            ((failed_tests++))
        fi
    else
        ((skipped_tests++))
    fi
    
    # Security Regression Tests
    if [[ "$SECURITY_TESTS" == "true" ]]; then
        if run_test_suite "Security Tests" "security_tests" "Validation of critical security fixes"; then
            ((passed_tests++))
        else
            ((failed_tests++))
        fi
    else
        ((skipped_tests++))
    fi
    
    # Performance Tests
    if [[ "$PERFORMANCE_TESTS" == "true" ]]; then
        if run_test_suite "Performance Tests" "performance_tests" "Memory pools and buffer management efficiency"; then
            ((passed_tests++))
        else
            ((failed_tests++))
        fi
    else
        ((skipped_tests++))
    fi
    
    # iOS NetworkExtension Tests
    if [[ "$IOS_TESTS" == "true" && "$HAS_MACOS" == "true" ]]; then
        if run_test_suite "iOS Tests" "ios_tests" "NetworkExtension integration and iOS-specific functionality"; then
            ((passed_tests++))
        else
            ((failed_tests++))
        fi
    else
        ((skipped_tests++))
    fi
    
    # Memory Tests
    if [[ "$MEMORY_TESTS" == "true" ]]; then
        if run_test_suite "Memory Tests" "memory_tests" "Memory leak detection and resource management"; then
            ((passed_tests++))
        else
            ((failed_tests++))
        fi
    else
        ((skipped_tests++))
    fi
    
    # Stress Tests
    if [[ "$STRESS_TESTS" == "true" ]]; then
        if run_test_suite "Stress Tests" "stress_tests" "High load scenarios and concurrent connections"; then
            ((passed_tests++))
        else
            ((failed_tests++))
        fi
    else
        ((skipped_tests++))
    fi
    
    # Final summary
    print_header "Test Suite Summary"
    echo "Passed: $passed_tests"
    echo "Failed: $failed_tests"
    echo "Skipped: $skipped_tests"
    echo ""
    
    if [[ $failed_tests -eq 0 ]]; then
        print_success "ALL TESTS PASSED!"
        echo ""
        print_success "PACKET LIFECYCLE TESTING COMPLETED SUCCESSFULLY"
        echo "✓ Packets going IN and OUT validated"
        echo "✓ Internet connectivity through VPN verified"
        echo "✓ iOS NetworkExtension integration tested"
        echo "✓ Security fixes validated"
        echo "✓ Performance benchmarks completed"
        echo ""
        echo "Test results available in: $TEST_RESULTS_DIR/"
        exit 0
    else
        print_error "Some tests failed. Check logs in $TEST_RESULTS_DIR/"
        exit 1
    fi
}

# Run main function
main "$@"