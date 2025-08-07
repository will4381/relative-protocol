/**
 * iOS VPN Module Test
 * Verifies packet parsing and connection tracking works
 */

#include "ios_vpn.h" 
#include <stdio.h>
#include <assert.h>
#include <string.h>
#include <arpa/inet.h>

void test_ios_vpn_initialization() {
    printf("Testing iOS VPN initialization...\n");
    
    bool initialized = ios_vpn_init();
    assert(initialized == true);
    
    // Initialize again should succeed
    bool init_again = ios_vpn_init();
    assert(init_again == true);
    
    ios_vpn_cleanup();
    printf("✅ iOS VPN initialization works\n");
}

void test_packet_parsing() {
    printf("Testing packet parsing...\n");
    
    ios_vpn_init();
    
    // Create IPv4 TCP packet
    uint8_t tcp_packet[] = {
        0x45, 0x00, 0x00, 0x28,  // IP header: Version 4, IHL 5, Total Length 40
        0x12, 0x34, 0x40, 0x00,  // ID, Flags, Fragment Offset
        0x40, 0x06, 0x00, 0x00,  // TTL, Protocol (TCP), Checksum
        0xc0, 0x00, 0x02, 0x01,  // Source IP (192.0.2.1)
        0xc0, 0x00, 0x02, 0x02,  // Dest IP (192.0.2.2)
        0x04, 0xd2, 0x00, 0x50,  // Source Port (1234), Dest Port (80)
        0x12, 0x34, 0x56, 0x78,  // Sequence Number
        0x9a, 0xbc, 0xde, 0xf0,  // Acknowledgment Number
        0x50, 0x18, 0x20, 0x00,  // Header Length, Flags, Window
        0x00, 0x00, 0x00, 0x00   // Checksum, Urgent Pointer
    };
    
    packet_info_t info;
    bool parsed = ios_vpn_parse_packet(tcp_packet, sizeof(tcp_packet), &info);
    
    assert(parsed == true);
    assert(info.flow.ip_version == 4);
    assert(info.flow.protocol == 6); // TCP
    assert(info.flow.src_ip == 0x010200c0); // 192.0.2.1 (as memcpy'd)
    assert(info.flow.dst_ip == 0x020200c0); // 192.0.2.2 (as memcpy'd)
    assert(info.flow.src_port == 1234);
    assert(info.flow.dst_port == 80);
    assert(info.header_length == 20);
    
    ios_vpn_cleanup();
    printf("✅ Packet parsing works\n");
}

void test_connection_tracking() {
    printf("Testing connection tracking...\n");
    
    ios_vpn_init();
    
    // Create flow info
    flow_info_t flow = {
        .src_ip = 0x010200c0, // 192.0.2.1 (network byte order)
        .dst_ip = 0x08080808, // 8.8.8.8
        .src_port = 12345,
        .dst_port = 80,
        .protocol = 6, // TCP
        .ip_version = 4
    };
    
    // Track connection
    connection_handle_t conn1 = ios_vpn_track_connection(&flow);
    assert(conn1 != NULL);
    
    // Track same connection again - should return same handle
    connection_handle_t conn2 = ios_vpn_track_connection(&flow);
    assert(conn2 == conn1);
    
    // Find connection
    connection_handle_t found = ios_vpn_find_connection(0x010200c0, 12345, 6);
    assert(found == conn1);
    
    // Get flow info
    flow_info_t retrieved_flow;
    bool got_flow = ios_vpn_get_connection_flow(conn1, &retrieved_flow);
    assert(got_flow == true);
    assert(retrieved_flow.src_ip == flow.src_ip);
    assert(retrieved_flow.dst_ip == flow.dst_ip);
    assert(retrieved_flow.src_port == flow.src_port);
    assert(retrieved_flow.dst_port == flow.dst_port);
    assert(retrieved_flow.protocol == flow.protocol);
    
    // Remove connection
    ios_vpn_remove_connection(conn1);
    
    // Should not find it anymore
    connection_handle_t not_found = ios_vpn_find_connection(0x010200c0, 12345, 6);
    assert(not_found == NULL);
    
    ios_vpn_cleanup();
    printf("✅ Connection tracking works\n");
}

void test_dns_detection() {
    printf("Testing DNS packet detection...\n");
    
    // Create packet info for DNS query
    packet_info_t dns_info = {
        .flow = {
            .protocol = 17, // UDP
            .dst_port = 53  // DNS port
        }
    };
    
    bool is_dns = ios_vpn_is_dns_packet(&dns_info);
    assert(is_dns == true);
    
    // Create non-DNS packet
    packet_info_t http_info = {
        .flow = {
            .protocol = 6,  // TCP
            .dst_port = 80  // HTTP port
        }
    };
    
    bool is_not_dns = ios_vpn_is_dns_packet(&http_info);
    assert(is_not_dns == false);
    
    printf("✅ DNS detection works\n");
}

void test_ipv6_parsing() {
    printf("Testing IPv6 packet parsing...\n");
    
    // Create IPv6 UDP packet
    uint8_t ipv6_packet[] = {
        0x60, 0x00, 0x00, 0x00,  // Version 6, Traffic Class, Flow Label
        0x00, 0x08, 0x11, 0x40,  // Payload Length (8), Next Header (UDP), Hop Limit
        // Source address: 2001:db8::1
        0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
        // Dest address: 2001:db8::2
        0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02,
        // UDP header
        0x04, 0xd2, 0x00, 0x35, 0x00, 0x08, 0x00, 0x00
    };
    
    flow_info_v6_t flow_v6;
    bool parsed = ios_vpn_parse_packet_v6(ipv6_packet, sizeof(ipv6_packet), &flow_v6);
    
    assert(parsed == true);
    assert(flow_v6.protocol == 17); // UDP
    assert(flow_v6.src_port == 1234);
    assert(flow_v6.dst_port == 53);
    
    // Check source address
    uint8_t expected_src[] = {0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00,
                             0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01};
    assert(memcmp(flow_v6.src_ip, expected_src, 16) == 0);
    
    printf("✅ IPv6 packet parsing works\n");
}

void test_nat64_detection() {
    printf("Testing NAT64 detection...\n");
    
    // Create IPv6 flow with IPv4-mapped prefix
    flow_info_v6_t nat64_flow = {0};
    // Set destination to ::ffff:808:808 (8.8.8.8 IPv4-mapped)
    nat64_flow.dst_ip[10] = 0xFF; nat64_flow.dst_ip[11] = 0xFF;
    nat64_flow.dst_ip[12] = 8; nat64_flow.dst_ip[13] = 8;
    nat64_flow.dst_ip[14] = 8; nat64_flow.dst_ip[15] = 8;
    
    bool needs_nat64 = ios_vpn_needs_nat64(&nat64_flow);
    assert(needs_nat64 == true);
    
    // Create regular IPv6 flow
    flow_info_v6_t regular_flow = {0};
    regular_flow.dst_ip[0] = 0x20; regular_flow.dst_ip[1] = 0x01; // 2001:db8::
    regular_flow.dst_ip[2] = 0x0d; regular_flow.dst_ip[3] = 0xb8;
    
    bool no_nat64 = ios_vpn_needs_nat64(&regular_flow);
    assert(no_nat64 == false);
    
    printf("✅ NAT64 detection works\n");
}

void test_packet_building() {
    printf("Testing response packet building...\n");
    
    // Original flow
    flow_info_t original_flow = {
        .src_ip = 0x010200c0, // 192.0.2.1 (network byte order)
        .dst_ip = 0x08080808, // 8.8.8.8
        .src_port = 12345,
        .dst_port = 80,
        .protocol = 6, // TCP
        .ip_version = 4
    };
    
    const char *response_data = "HTTP/1.1 200 OK\r\n\r\n";
    uint8_t buffer[200];
    
    size_t packet_size = ios_vpn_build_response_packet(
        &original_flow,
        (const uint8_t*)response_data,
        strlen(response_data),
        buffer,
        sizeof(buffer)
    );
    
    assert(packet_size > 0);
    assert(packet_size == 20 + 20 + strlen(response_data)); // IP + TCP + payload
    
    // Verify IP header
    assert(buffer[0] == 0x45); // Version 4, IHL 5
    assert(buffer[9] == 6); // Protocol TCP
    
    // Verify addresses are swapped (response packet)
    uint32_t response_src, response_dst;
    memcpy(&response_src, &buffer[12], 4);
    memcpy(&response_dst, &buffer[16], 4);
    assert(response_src == original_flow.dst_ip); // Source = original dest
    assert(response_dst == original_flow.src_ip); // Dest = original source
    
    printf("✅ Response packet building works\n");
}

void test_statistics() {
    printf("Testing VPN statistics...\n");
    
    ios_vpn_init();
    
    vpn_stats_t stats;
    ios_vpn_get_stats(&stats);
    
    uint64_t initial_packets = stats.packets_processed;
    
    // Parse a packet to increment stats
    uint8_t simple_packet[] = {
        0x45, 0x00, 0x00, 0x14,  // Minimal IP header
        0x00, 0x00, 0x00, 0x00,
        0x40, 0x01, 0x00, 0x00,  // Protocol ICMP
        0x7f, 0x00, 0x00, 0x01,  // Source: 127.0.0.1
        0x7f, 0x00, 0x00, 0x01   // Dest: 127.0.0.1
    };
    
    packet_info_t info;
    ios_vpn_parse_packet(simple_packet, sizeof(simple_packet), &info);
    
    ios_vpn_get_stats(&stats);
    assert(stats.packets_processed == initial_packets + 1);
    
    ios_vpn_cleanup();
    printf("✅ VPN statistics work\n");
}

int main() {
    printf("\n=== iOS VPN Module Tests ===\n\n");
    
    test_ios_vpn_initialization();
    test_packet_parsing();
    test_connection_tracking();
    test_dns_detection();
    test_ipv6_parsing();
    test_nat64_detection();
    test_packet_building();
    test_statistics();
    
    printf("\n✅ All iOS VPN tests passed!\n\n");
    return 0;
}