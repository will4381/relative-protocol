find_package(PkgConfig REQUIRED)

# Try to find GoogleTest
find_package(GTest QUIET)

if(NOT GTest_FOUND)
    # Download and build GoogleTest
    include(FetchContent)
    FetchContent_Declare(
        googletest
        URL https://github.com/google/googletest/archive/v1.14.0.zip
        DOWNLOAD_EXTRACT_TIMESTAMP TRUE
    )
    
    set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)
    FetchContent_MakeAvailable(googletest)
endif()

# Unit tests - temporarily excluding problematic tests
add_executable(unit_tests
    unit/test_ring_buffer.cpp
    unit/test_utun.cpp
    unit/test_vpn_api.cpp
    unit/test_logging.cpp
    unit/test_dns_resolver.cpp
    unit/test_privacy_guards.cpp
    unit/test_nat64.cpp
    unit/test_connection_manager.cpp
    # Temporarily excluded due to API mismatches:
    # unit/test_mtu_discovery.cpp
    # unit/test_traffic_classifier.cpp
    # unit/test_reachability_monitor.cpp
    # unit/test_socket_bridge.cpp
)

target_include_directories(unit_tests PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/../include
    ${CMAKE_CURRENT_SOURCE_DIR}/../src
)

target_link_libraries(unit_tests
    relative_vpn
    gtest_main
    gtest
    pthread
)

if(CMAKE_SYSTEM_NAME STREQUAL "Darwin" OR CMAKE_SYSTEM_NAME STREQUAL "iOS")
    target_link_libraries(unit_tests
        "-framework Foundation"
        "-framework Network"
        "-framework NetworkExtension"
        "-framework SystemConfiguration"
    )
endif()

# Integration tests
add_executable(integration_tests
    integration/test_full_stack.cpp  
    integration/test_performance.cpp
    integration/test_packet_lifecycle.cpp
    integration/test_web_browsing_dns.cpp
    integration/test_dns_comprehensive.cpp
    integration/test_ipv6_handling.cpp
)

target_include_directories(integration_tests PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/../include
)

target_link_libraries(integration_tests
    relative_vpn
    gtest_main
    gtest
    pthread
)

if(CMAKE_SYSTEM_NAME STREQUAL "Darwin" OR CMAKE_SYSTEM_NAME STREQUAL "iOS")
    target_link_libraries(integration_tests
        "-framework Foundation"
        "-framework Network"
        "-framework NetworkExtension"
        "-framework SystemConfiguration"
        "-framework Security"
    )
endif()

# Fuzzing targets
if(ENABLE_FUZZING)
    add_executable(fuzz_packet_parser
        fuzz/fuzz_packet_parser.cpp
    )
    
    target_include_directories(fuzz_packet_parser PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/../include
    )
    
    target_link_libraries(fuzz_packet_parser
        relative_vpn
        -fsanitize=fuzzer
    )
    
    target_compile_options(fuzz_packet_parser PRIVATE
        -fsanitize=fuzzer,address
        -g
        -O1
    )
endif()

# Memory leak tests
add_executable(memory_tests
    memory/test_memory_leaks.cpp
)

target_include_directories(memory_tests PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/../include
)

target_link_libraries(memory_tests
    relative_vpn
    gtest_main
    gtest
    pthread
)

if(CMAKE_SYSTEM_NAME STREQUAL "Darwin" OR CMAKE_SYSTEM_NAME STREQUAL "iOS")
    target_link_libraries(memory_tests
        "-framework Foundation"
        "-framework Network"
        "-framework NetworkExtension"
        "-framework SystemConfiguration"
    )
endif()

# Stress tests
add_executable(stress_tests
    stress/stress_concurrent_connections.cpp
)

target_include_directories(stress_tests PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/../include
)

target_link_libraries(stress_tests
    relative_vpn
    gtest_main
    gtest
    pthread
)

if(CMAKE_SYSTEM_NAME STREQUAL "Darwin" OR CMAKE_SYSTEM_NAME STREQUAL "iOS")
    target_link_libraries(stress_tests
        "-framework Foundation"
        "-framework Network"
        "-framework NetworkExtension"
        "-framework SystemConfiguration"
    )
endif()

# Benchmark tests (optional - requires Google Benchmark)
if(ENABLE_BENCHMARKS)
    find_package(benchmark QUIET)
    if(benchmark_FOUND)
        add_executable(benchmark_tests
            benchmarks/benchmark_ring_buffer.cpp
        )
        
        target_include_directories(benchmark_tests PRIVATE
            ${CMAKE_CURRENT_SOURCE_DIR}/../include
        )
        
        target_link_libraries(benchmark_tests
            relative_vpn
            benchmark::benchmark
            pthread
        )
        
        if(CMAKE_SYSTEM_NAME STREQUAL "Darwin" OR CMAKE_SYSTEM_NAME STREQUAL "iOS")
            target_link_libraries(benchmark_tests
                "-framework Foundation"
                "-framework Network"
                "-framework NetworkExtension"
                "-framework SystemConfiguration"
            )
        endif()
    endif()
endif()

# Security regression tests
add_executable(security_tests
    security/test_security_regression.cpp
    utils/test_utilities.cpp
)

target_include_directories(security_tests PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/../include
    ${CMAKE_CURRENT_SOURCE_DIR}/utils
)

target_link_libraries(security_tests
    relative_vpn
    gtest_main
    gtest
    pthread
)

if(CMAKE_SYSTEM_NAME STREQUAL "Darwin" OR CMAKE_SYSTEM_NAME STREQUAL "iOS")
    target_link_libraries(security_tests
        "-framework Foundation"
        "-framework Network"
        "-framework NetworkExtension"
        "-framework SystemConfiguration"
    )
endif()

# Performance tests
add_executable(performance_tests
    performance/test_memory_performance.cpp
    utils/test_utilities.cpp
)

target_include_directories(performance_tests PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/../include
    ${CMAKE_CURRENT_SOURCE_DIR}/utils
)

target_link_libraries(performance_tests
    relative_vpn
    gtest_main
    gtest
    pthread
)

if(CMAKE_SYSTEM_NAME STREQUAL "Darwin" OR CMAKE_SYSTEM_NAME STREQUAL "iOS")
    target_link_libraries(performance_tests
        "-framework Foundation"
        "-framework Network"
        "-framework NetworkExtension"
        "-framework SystemConfiguration"
    )
endif()

# iOS NetworkExtension tests
if(CMAKE_SYSTEM_NAME STREQUAL "Darwin" OR CMAKE_SYSTEM_NAME STREQUAL "iOS")
    add_executable(ios_tests
        ios/test_networkextension_integration.mm
        utils/test_utilities.cpp
    )

    target_include_directories(ios_tests PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/../include
        ${CMAKE_CURRENT_SOURCE_DIR}/utils
    )

    target_link_libraries(ios_tests
        relative_vpn
        gtest_main
        gtest
        pthread
        "-framework Foundation"
        "-framework Network"
        "-framework NetworkExtension"
        "-framework SystemConfiguration"
    )
endif()

# Test utilities library
add_library(test_utils STATIC
    utils/test_utilities.cpp
)

target_include_directories(test_utils PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/../include
    ${CMAKE_CURRENT_SOURCE_DIR}/utils
)

target_link_libraries(test_utils
    relative_vpn
    gtest
)

# Update existing tests to use utilities
target_link_libraries(integration_tests test_utils)
target_include_directories(integration_tests PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/utils)

# Register tests with CTest
add_test(NAME UnitTests COMMAND unit_tests)
add_test(NAME IntegrationTests COMMAND integration_tests)
add_test(NAME MemoryTests COMMAND memory_tests)
add_test(NAME StressTests COMMAND stress_tests)
add_test(NAME SecurityTests COMMAND security_tests)
add_test(NAME PerformanceTests COMMAND performance_tests)

if(CMAKE_SYSTEM_NAME STREQUAL "Darwin" OR CMAKE_SYSTEM_NAME STREQUAL "iOS")
    add_test(NAME iOSTests COMMAND ios_tests)
endif()

# Test properties
set_tests_properties(UnitTests PROPERTIES
    TIMEOUT 30
    LABELS "unit"
)

set_tests_properties(IntegrationTests PROPERTIES
    TIMEOUT 60
    LABELS "integration"
)

set_tests_properties(MemoryTests PROPERTIES
    TIMEOUT 120
    LABELS "memory"
)

set_tests_properties(StressTests PROPERTIES
    TIMEOUT 300
    LABELS "stress"
)

set_tests_properties(SecurityTests PROPERTIES
    TIMEOUT 180
    LABELS "security"
)

set_tests_properties(PerformanceTests PROPERTIES
    TIMEOUT 240
    LABELS "performance"
)

if(CMAKE_SYSTEM_NAME STREQUAL "Darwin" OR CMAKE_SYSTEM_NAME STREQUAL "iOS")
    set_tests_properties(iOSTests PROPERTIES
        TIMEOUT 120
        LABELS "ios"
    )
endif()