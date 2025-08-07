/**
 * Logging Test Example
 * 
 * This example demonstrates how to enable extensive logging in the RelativeProtocol VPN
 * to debug network connectivity and packet forwarding issues.
 */

#include "api/relative_vpn.h"
#include "core/logging.h"
#include "ios_vpn.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

// Example log callback function
void log_callback(const char *message, void *user_data) {
    printf("[VPN] %s\n", message);
    fflush(stdout);
}

// Example test packet (IPv4 TCP SYN)
uint8_t test_packet[] = {
    0x45, 0x00, 0x00, 0x3c, 0x12, 0x34, 0x40, 0x00,  // IP header
    0x40, 0x06, 0x00, 0x00, 0xc0, 0xa8, 0x01, 0x02,  // IP header cont. (192.168.1.2)
    0xc0, 0xa8, 0x01, 0x01, 0x04, 0xd2, 0x00, 0x50,  // IP dest (192.168.1.1), TCP src:1234, dst:80
    0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,  // TCP header
    0x50, 0x02, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00   // TCP header cont.
};

int main() {
    printf("RelativeProtocol VPN Logging Test\n");
    printf("==================================\n\n");
    
    // Initialize logging at TRACE level for maximum verbosity
    printf("1. Setting up extensive logging...\n");
    log_init(LOG_TRACE);
    
    // Set custom log callback to capture all log messages
    log_set_callback(log_callback, NULL);
    
    // Initialize iOS VPN module
    printf("\n2. Initializing iOS VPN module...\n");
    if (!ios_vpn_init()) {
        printf("Failed to initialize iOS VPN module!\n");
        return 1;
    }
    
    // Create VPN configuration with extensive logging
    vpn_config_t config = {0};
    config.mtu = 1500;
    config.ipv4_enabled = true;
    config.ipv6_enabled = true;
    config.enable_nat64 = true;
    config.log_level = "TRACE";  // Enable maximum logging
    
    printf("\n3. Starting VPN with TRACE logging...\n");
    vpn_status_t status = vpn_start(&config);
    if (status != VPN_SUCCESS) {
        printf("Failed to start VPN: %s\n", vpn_error_string(status));
        return 1;
    }
    
    printf("\n4. Testing packet parsing with extensive logging...\n");
    packet_info_t packet_info;
    
    // Parse the test packet - this will generate extensive logging
    printf("   Parsing test TCP packet...\n");
    if (ios_vpn_parse_packet(test_packet, sizeof(test_packet), &packet_info)) {
        printf("   ✓ Packet parsed successfully\n");
    } else {
        printf("   ✗ Packet parsing failed\n");
    }
    
    printf("\n5. Testing different log levels...\n");
    
    // Test different log levels
    const char* levels[] = {"TRACE", "DEBUG", "INFO", "WARN", "ERROR", "CRITICAL", "SILENT"};
    
    for (int i = 0; i < 7; i++) {
        printf("   Setting log level to %s...\n", levels[i]);
        vpn_set_log_level(levels[i]);
        
        // Test logging at this level
        LOG_CRITICAL("Critical message test");
        LOG_ERROR("Error message test");
        LOG_WARN("Warning message test");
        LOG_INFO("Info message test");
        LOG_DEBUG("Debug message test");
        LOG_TRACE("Trace message test");
        
        usleep(100000); // 100ms delay
    }
    
    printf("\n6. Testing packet injection with logging...\n");
    vpn_set_log_level("DEBUG");  // Set to DEBUG for packet injection
    
    // Inject the test packet - this will show packet details
    status = vpn_inject(test_packet, sizeof(test_packet));
    if (status == VPN_SUCCESS) {
        printf("   ✓ Packet injected successfully\n");
    } else {
        printf("   ✗ Packet injection failed: %s\n", vpn_error_string(status));
    }
    
    printf("\n7. Demonstrating connection tracking logging...\n");
    
    // Create a flow from the parsed packet
    flow_info_t flow = packet_info.flow;
    
    // Track the connection - this will generate connection tracking logs
    connection_handle_t conn = ios_vpn_track_connection(&flow);
    if (conn) {
        printf("   ✓ Connection tracked successfully\n");
        
        // Try to find the same connection
        connection_handle_t found_conn = ios_vpn_find_connection(flow.dst_ip, flow.dst_port, flow.protocol);
        if (found_conn) {
            printf("   ✓ Connection found in tracking table\n");
        }
    }
    
    printf("\n8. Testing packet building with logging...\n");
    
    // Test response packet building
    uint8_t response_data[] = "HTTP/1.1 200 OK\r\n\r\nHello World!";
    uint8_t response_buffer[1500];
    
    size_t response_size = ios_vpn_build_response_packet(
        &flow, response_data, sizeof(response_data) - 1, 
        response_buffer, sizeof(response_buffer)
    );
    
    if (response_size > 0) {
        printf("   ✓ Response packet built: %zu bytes\n", response_size);
    } else {
        printf("   ✗ Response packet building failed\n");
    }
    
    printf("\n9. Cleanup...\n");
    
    // Stop VPN
    vpn_stop();
    
    // Cleanup iOS VPN
    ios_vpn_cleanup();
    
    printf("\n✓ Test completed successfully!\n");
    printf("\nTo use extensive logging in your app:\n");
    printf("1. Call vpn_set_log_level(\"TRACE\") for maximum verbosity\n");
    printf("2. Call vpn_set_log_callback() to capture log messages\n");
    printf("3. Available log levels: TRACE, DEBUG, INFO, WARN, ERROR, CRITICAL, SILENT\n");
    printf("4. TRACE level shows every packet detail, header parsing, and forwarding step\n");
    
    return 0;
}