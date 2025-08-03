# Cross-platform sources that work everywhere
set(RELATIVE_VPN_SOURCES
    core/logging.c
    packet/buffer_manager.c
    tcp_udp/connection_manager.c
    dns/resolver.c
    dns/cache.c
    metrics/ring_buffer.c
    nat64/translator.c
    mtu/discovery.c
    classifier/tls_quic.c
    privacy/guards.c
    api/vpn_api.c
    api/vpn_engine.c
)

# Add platform-specific sources
if(CMAKE_SYSTEM_NAME STREQUAL "iOS")
    # iOS uses NetworkExtension framework - exclude macOS-specific components
    message(STATUS "Building for iOS - excluding macOS-specific components")
    # iOS versions of these would be implemented differently using NetworkExtension
else()
    # macOS can use direct kernel APIs and Objective-C imports
    list(APPEND RELATIVE_VPN_SOURCES
        packet/utun.c
        socket_bridge/bridge.c
        reachability/monitor.c
        crash/reporter.c
    )
endif()

# Core headers that work on all platforms
set(RELATIVE_VPN_HEADERS
    ${CMAKE_CURRENT_SOURCE_DIR}/../include/api/relative_vpn.h
    ${CMAKE_CURRENT_SOURCE_DIR}/../include/core/types.h
    ${CMAKE_CURRENT_SOURCE_DIR}/../include/core/logging.h
    ${CMAKE_CURRENT_SOURCE_DIR}/../include/packet/buffer_manager.h
    ${CMAKE_CURRENT_SOURCE_DIR}/../include/metrics/ring_buffer.h
)

# Add platform-specific headers
if(NOT CMAKE_SYSTEM_NAME STREQUAL "iOS")
    list(APPEND RELATIVE_VPN_HEADERS
        ${CMAKE_CURRENT_SOURCE_DIR}/../include/packet/utun.h
    )
endif()

if(BUILD_STATIC)
    add_library(relative_vpn STATIC ${RELATIVE_VPN_SOURCES})
else()
    add_library(relative_vpn SHARED ${RELATIVE_VPN_SOURCES})
endif()

target_link_libraries(relative_vpn
    pthread
)

if(CMAKE_SYSTEM_NAME STREQUAL "Darwin" OR CMAKE_SYSTEM_NAME STREQUAL "iOS")
    target_link_libraries(relative_vpn
        "-framework Foundation"
        "-framework Network"
        "-framework NetworkExtension"
        "-framework SystemConfiguration"
        "-framework Security"
    )
endif()

set_target_properties(relative_vpn PROPERTIES
    VERSION ${PROJECT_VERSION}
    SOVERSION ${PROJECT_VERSION_MAJOR}
    PUBLIC_HEADER "${RELATIVE_VPN_HEADERS}"
)

install(TARGETS relative_vpn
    LIBRARY DESTINATION lib
    ARCHIVE DESTINATION lib
    PUBLIC_HEADER DESTINATION include/relative_vpn
)