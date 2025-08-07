# iOS VPN Framework - Core Working Modules Only
# All fake/placeholder implementations have been removed

set(RELATIVE_VPN_SOURCES
    # Core utilities
    core/logging.c
    
    # Memory management  
    packet/buffer_manager.c
    
    # iOS NetworkExtension integration
    packet/tunnel_provider.mm
    
    # Network protocol handling
    tcp_udp/connection_manager.c
    dns/resolver.c
    nat64/translator.c
    
    # Main iOS VPN module
    ios_vpn.c
    
    # VPN API implementation
    vpn_api.c
    
    # Metrics and utilities
    metrics/ring_buffer.c
)

# Core headers that work on all platforms
set(RELATIVE_VPN_HEADERS
    ${CMAKE_CURRENT_SOURCE_DIR}/../include/RelativeProtocol.h
    ${CMAKE_CURRENT_SOURCE_DIR}/../include/api/relative_vpn.h
    ${CMAKE_CURRENT_SOURCE_DIR}/../include/core/types.h
    ${CMAKE_CURRENT_SOURCE_DIR}/../include/core/logging.h
    ${CMAKE_CURRENT_SOURCE_DIR}/../include/packet/buffer_manager.h
    ${CMAKE_CURRENT_SOURCE_DIR}/../include/packet/tunnel_provider.h
    ${CMAKE_CURRENT_SOURCE_DIR}/../include/tcp_udp/connection_manager.h
    ${CMAKE_CURRENT_SOURCE_DIR}/../include/dns/resolver.h
    ${CMAKE_CURRENT_SOURCE_DIR}/../include/nat64/translator.h
    ${CMAKE_CURRENT_SOURCE_DIR}/../include/metrics/ring_buffer.h
    ${CMAKE_CURRENT_SOURCE_DIR}/../include/ios_vpn.h
)

# Build library
if(BUILD_STATIC)
    add_library(relative_vpn STATIC ${RELATIVE_VPN_SOURCES})
else()
    add_library(relative_vpn SHARED ${RELATIVE_VPN_SOURCES})
endif()

# Link libraries
target_link_libraries(relative_vpn
    pthread
)

# iOS/macOS specific frameworks
if(CMAKE_SYSTEM_NAME STREQUAL "Darwin" OR CMAKE_SYSTEM_NAME STREQUAL "iOS")
    target_link_libraries(relative_vpn
        "-framework Foundation"
        "-framework Network" 
        "-framework NetworkExtension"
        "-framework SystemConfiguration"
        "-framework Security"
        "-framework CoreTelephony"
    )
    
    # Set iOS-specific properties
    set_target_properties(relative_vpn PROPERTIES
        FRAMEWORK TRUE
        FRAMEWORK_VERSION A
        MACOSX_FRAMEWORK_IDENTIFIER com.relative.vpn
        PUBLIC_HEADER "${RELATIVE_VPN_HEADERS}"
    )
endif()

# Library properties
set_target_properties(relative_vpn PROPERTIES
    VERSION ${PROJECT_VERSION}
    SOVERSION ${PROJECT_VERSION_MAJOR}
    PUBLIC_HEADER "${RELATIVE_VPN_HEADERS}"
    C_STANDARD 11
    CXX_STANDARD 17
)

# Compiler-specific settings
target_compile_definitions(relative_vpn PRIVATE
    $<$<CONFIG:Debug>:DEBUG=1>
    $<$<CONFIG:Release>:NDEBUG>
    $<$<BOOL:${ENABLE_LOGGING}>:ENABLE_LOGGING=1>
)

# Installation rules
install(TARGETS relative_vpn
    LIBRARY DESTINATION lib
    ARCHIVE DESTINATION lib
    FRAMEWORK DESTINATION /Library/Frameworks
    PUBLIC_HEADER DESTINATION include/relative_vpn
)

# Install iOS VPN header separately (it's not in subdirectories)
install(FILES ${CMAKE_CURRENT_SOURCE_DIR}/../include/ios_vpn.h
    DESTINATION include/relative_vpn
)

# Create module.modulemap for Swift Package Manager
if(CMAKE_SYSTEM_NAME STREQUAL "iOS")
    set(MODULE_MAP_CONTENT "module RelativeProtocol [system] {
    umbrella header \"RelativeProtocol.h\"
    
    // Export all public headers
    export *
    module * { export * }
    
    // Link required system libraries  
    link \"pthread\"
    
    // iOS-specific frameworks
    link framework \"NetworkExtension\"
    link framework \"Network\"
    link framework \"CoreTelephony\"
}")
    
    # Write module.modulemap to both framework and include directory
    file(WRITE "${CMAKE_CURRENT_BINARY_DIR}/relative_vpn.framework/Headers/module.modulemap" "${MODULE_MAP_CONTENT}")
    file(WRITE "${CMAKE_CURRENT_SOURCE_DIR}/../include/module.modulemap" "${MODULE_MAP_CONTENT}")
    
    # Create proper Info.plist for the framework
    set(FRAMEWORK_PLIST_CONTENT "<?xml version=\"1.0\" encoding=\"UTF-8\"?>
<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">
<plist version=\"1.0\">
<dict>
    <key>CFBundleIdentifier</key>
    <string>com.relativeprotocol.framework</string>
    <key>CFBundleName</key>
    <string>RelativeProtocol</string>
    <key>CFBundleVersion</key>
    <string>1.0.0</string>
    <key>CFBundleShortVersionString</key>
    <string>1.0.0</string>
    <key>CFBundlePackageType</key>
    <string>FMWK</string>
    <key>CFBundleExecutable</key>
    <string>relative_vpn</string>
    <key>MinimumOSVersion</key>
    <string>14.0</string>
</dict>
</plist>")
    
    file(WRITE "${CMAKE_CURRENT_BINARY_DIR}/relative_vpn.framework/Info.plist" "${FRAMEWORK_PLIST_CONTENT}")
    
    # Copy all headers to framework Headers directory for proper Swift exposure
    add_custom_command(TARGET relative_vpn POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy_directory
            "${CMAKE_CURRENT_SOURCE_DIR}/../include"
            "${CMAKE_CURRENT_BINARY_DIR}/relative_vpn.framework/Headers"
        COMMENT "Copying all headers to framework for Swift Package Manager"
    )
endif()

# XCFramework target for iOS distribution
if(BUILD_XCFRAMEWORK AND CMAKE_SYSTEM_NAME STREQUAL "iOS")
    add_custom_target(xcframework
        COMMAND xcodebuild -create-xcframework 
            -framework ${CMAKE_CURRENT_BINARY_DIR}/relative_vpn.framework
            -output ${CMAKE_CURRENT_BINARY_DIR}/../RelativeVPN.xcframework
        DEPENDS relative_vpn
        COMMENT "Creating XCFramework for iOS distribution with Swift Package Manager support"
    )
endif()

# Print source file summary
message(STATUS "RelativeProtocol sources: ${RELATIVE_VPN_SOURCES}")
message(STATUS "Public headers: ${RELATIVE_VPN_HEADERS}")