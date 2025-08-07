cmake_minimum_required(VERSION 3.20)

# Set project name and version
project(RelativeProtocol
    VERSION 1.0.0
    DESCRIPTION "iOS VPN Framework using NetworkExtension"
    LANGUAGES C CXX OBJC OBJCXX
)

# Set C and C++ standards
set(CMAKE_C_STANDARD 11)
set(CMAKE_CXX_STANDARD 17)

# Enable position independent code
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

# Platform-specific settings
if(CMAKE_SYSTEM_NAME STREQUAL "Darwin" OR CMAKE_SYSTEM_NAME STREQUAL "iOS")
    set(CMAKE_OSX_DEPLOYMENT_TARGET "13.0")
    enable_language(OBJC)
    enable_language(OBJCXX)
endif()

# Build configuration options
option(BUILD_STATIC "Build static library" ON)
option(BUILD_TESTS "Build test suite" OFF)
option(BUILD_EXAMPLES "Build example applications" OFF)
option(BUILD_XCFRAMEWORK "Build XCFramework" OFF)
option(ENABLE_TESTS "Enable test suite" OFF)
option(ENABLE_FUZZING "Enable fuzzing" OFF)
option(ENABLE_ASAN "Enable AddressSanitizer" OFF)
option(ENABLE_LOGGING "Enable debug logging" ON)

# Map ENABLE_* to BUILD_* for compatibility
if(ENABLE_TESTS)
    set(BUILD_TESTS ON)
endif()

# Compiler flags
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -Wextra -Wno-unused-parameter")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall -Wextra -Wno-unused-parameter")

# Debug configuration
set(CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} -g -O0 -DDEBUG=1")
set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} -g -O0 -DDEBUG=1")

# Release configuration
set(CMAKE_C_FLAGS_RELEASE "${CMAKE_C_FLAGS_RELEASE} -O3 -DNDEBUG")
set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} -O3 -DNDEBUG")

# Include directories
include_directories(
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    ${CMAKE_CURRENT_SOURCE_DIR}/src
)

# Add subdirectories
add_subdirectory(src)

if(BUILD_TESTS)
    enable_testing()
    add_subdirectory(tests)
endif()

if(BUILD_EXAMPLES)
    add_subdirectory(examples)
endif()

# Print configuration summary
message(STATUS "=== RelativeProtocol Configuration ===")
message(STATUS "Build type: ${CMAKE_BUILD_TYPE}")
message(STATUS "Build static: ${BUILD_STATIC}")
message(STATUS "Build tests: ${BUILD_TESTS}")
message(STATUS "Build examples: ${BUILD_EXAMPLES}")
message(STATUS "C compiler: ${CMAKE_C_COMPILER}")
message(STATUS "CXX compiler: ${CMAKE_CXX_COMPILER}")
if(CMAKE_SYSTEM_NAME STREQUAL "Darwin" OR CMAKE_SYSTEM_NAME STREQUAL "iOS")
    message(STATUS "Target platform: ${CMAKE_SYSTEM_NAME}")
    message(STATUS "OSX deployment target: ${CMAKE_OSX_DEPLOYMENT_TARGET}")
endif()
message(STATUS "=====================================")