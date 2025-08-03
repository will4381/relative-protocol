cmake_minimum_required(VERSION 3.20)
project(RelativeVPN VERSION 1.0.0 LANGUAGES C CXX)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

option(ENABLE_TESTS "Enable unit tests" ON)
option(ENABLE_FUZZING "Enable fuzzing targets" OFF)
option(ENABLE_ASAN "Enable AddressSanitizer" OFF)
option(ENABLE_LOGGING "Enable debug logging" OFF)
option(BUILD_STATIC "Build static library" ON)
option(BUILD_XCFRAMEWORK "Build XCFramework for iOS" OFF)

if(ENABLE_LOGGING)
    add_compile_definitions(ENABLE_LOGGING=1)
else()
    add_compile_definitions(ENABLE_LOGGING=0)
endif()

if(ENABLE_ASAN)
    add_compile_options(-fsanitize=address -fno-omit-frame-pointer)
    add_link_options(-fsanitize=address)
endif()

if(CMAKE_SYSTEM_NAME STREQUAL "iOS")
    set(CMAKE_OSX_DEPLOYMENT_TARGET "12.0")
    set(CMAKE_XCODE_ATTRIBUTE_IPHONEOS_DEPLOYMENT_TARGET "12.0")
    add_compile_definitions(TARGET_OS_IOS=1)
endif()

include_directories(
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    ${CMAKE_CURRENT_SOURCE_DIR}/third_party/lwip/src/include
    ${CMAKE_CURRENT_SOURCE_DIR}/third_party/lwip/contrib/ports/unix/port/include
)

add_subdirectory(third_party)
add_subdirectory(src)

if(ENABLE_TESTS)
    enable_testing()
    add_subdirectory(tests)
endif()

if(BUILD_XCFRAMEWORK AND CMAKE_SYSTEM_NAME STREQUAL "iOS")
    include(cmake/XCFramework.cmake)
endif()