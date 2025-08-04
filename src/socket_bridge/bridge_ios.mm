#import <Foundation/Foundation.h>
#import <NetworkExtension/NetworkExtension.h>
#import <Network/Network.h>

extern "C" {
#include "socket_bridge/bridge.h"
#include "core/logging.h"

// Forward declarations that match bridge.c
typedef void* ios_tcp_connection_t;
typedef void* ios_udp_session_t;

// Objective-C bridge functions for iOS NetworkExtension integration

ios_tcp_connection_t* ios_create_tcp_connection(const char* host, uint16_t port) {
    if (!host) return NULL;
    
    @autoreleasepool {
        NSString *hostString = [NSString stringWithUTF8String:host];
        NWHostEndpoint *endpoint = [NWHostEndpoint endpointWithHostname:hostString port:[NSString stringWithFormat:@"%d", port]];
        
        // Note: In a real NetworkExtension, this would use the packet tunnel provider's createTCPConnection
        // For now, return a placeholder that indicates the connection was created
        return (ios_tcp_connection_t*)CFBridgingRetain(endpoint);
    }
}

ios_udp_session_t* ios_create_udp_session(uint16_t local_port) {
    @autoreleasepool {
        NWHostEndpoint *endpoint = [NWHostEndpoint endpointWithHostname:@"0.0.0.0" port:[NSString stringWithFormat:@"%d", local_port]];
        
        // Note: In a real NetworkExtension, this would use the packet tunnel provider's createUDPSession
        // For now, return a placeholder that indicates the session was created
        return (ios_udp_session_t*)CFBridgingRetain(endpoint);
    }
}

bool ios_send_tcp_data(ios_tcp_connection_t* conn, const uint8_t* data, size_t length) {
    if (!conn || !data || length == 0) return false;
    
    // Note: In a real implementation, this would send data through the TCP connection
    // For now, just log and return success
    LOG_DEBUG("iOS TCP send: %zu bytes", length);
    return true;
}

bool ios_send_udp_data(ios_udp_session_t* session, const uint8_t* data, size_t length, 
                       const char* dest_host, uint16_t dest_port) {
    if (!session || !data || length == 0 || !dest_host) return false;
    
    // Note: In a real implementation, this would send data through the UDP session
    // For now, just log and return success
    LOG_DEBUG("iOS UDP send: %zu bytes to %s:%d", length, dest_host, dest_port);
    return true;
}

void ios_close_tcp_connection(ios_tcp_connection_t* conn) {
    if (!conn) return;
    
    @autoreleasepool {
        CFBridgingRelease(conn);
    }
}

void ios_close_udp_session(ios_udp_session_t* session) {
    if (!session) return;
    
    @autoreleasepool {
        CFBridgingRelease(session);
    }
}

} // extern "C"