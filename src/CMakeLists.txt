# iOS-only VPN Framework - NetworkExtension compatible components
set(RELATIVE_VPN_SOURCES
    core/logging.c
    packet/buffer_manager.c
    packet/tunnel_provider.mm
    socket_bridge/bridge.c
    socket_bridge/bridge_ios.mm
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
    reachability/monitor.mm
    crash/reporter.mm
)

# iOS-only VPN framework using NEPacketTunnelProvider and NetworkExtension APIs
# All platform-specific code paths are handled via TARGET_OS_IOS conditionals

# Core headers that work on all platforms
set(RELATIVE_VPN_HEADERS
    ${CMAKE_CURRENT_SOURCE_DIR}/../include/api/relative_vpn.h
    ${CMAKE_CURRENT_SOURCE_DIR}/../include/core/types.h
    ${CMAKE_CURRENT_SOURCE_DIR}/../include/core/logging.h
    ${CMAKE_CURRENT_SOURCE_DIR}/../include/packet/buffer_manager.h
    ${CMAKE_CURRENT_SOURCE_DIR}/../include/metrics/ring_buffer.h
)

# iOS-specific headers
list(APPEND RELATIVE_VPN_HEADERS
    ${CMAKE_CURRENT_SOURCE_DIR}/../include/packet/tunnel_provider.h
    ${CMAKE_CURRENT_SOURCE_DIR}/../include/socket_bridge/bridge.h
)

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
        "-framework CoreTelephony"
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