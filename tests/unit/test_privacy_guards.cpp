#include <gtest/gtest.h>
#include "privacy/guards.h"
#include <thread>
#include <chrono>
#include <atomic>
#include <arpa/inet.h>  // For inet_addr

class PrivacyGuardsTest : public ::testing::Test {
protected:
    void SetUp() override {
        guards = privacy_guards_create();
        ASSERT_NE(guards, nullptr);
        
        // Set up allowed DNS servers
        allowed_dns[0] = { .v4 = { .addr = inet_addr("8.8.8.8") } };      // Google
        allowed_dns[1] = { .v4 = { .addr = inet_addr("1.1.1.1") } };      // Cloudflare
        allowed_dns[2] = { .v4 = { .addr = inet_addr("9.9.9.9") } };      // Quad9
        
        privacy_guards_set_allowed_dns_servers(guards, allowed_dns, 3);
    }
    
    void TearDown() override {
        if (guards) {
            privacy_guards_destroy(guards);
        }
    }
    
    privacy_guards_t *guards;
    ip_addr_t allowed_dns[3];
};

TEST_F(PrivacyGuardsTest, CreateDestroy) {
    EXPECT_NE(guards, nullptr);
    
    // Test default settings
    EXPECT_TRUE(privacy_guards_is_dns_leak_protection_enabled(guards));
    EXPECT_TRUE(privacy_guards_is_ipv6_leak_protection_enabled(guards));
    EXPECT_FALSE(privacy_guards_is_webrtc_leak_protection_enabled(guards));
    EXPECT_TRUE(privacy_guards_is_kill_switch_enabled(guards));
    EXPECT_FALSE(privacy_guards_is_kill_switch_active(guards));
}

TEST_F(PrivacyGuardsTest, ProtectionToggling) {
    // Test DNS leak protection
    EXPECT_TRUE(privacy_guards_enable_dns_leak_protection(guards, false));
    EXPECT_FALSE(privacy_guards_is_dns_leak_protection_enabled(guards));
    EXPECT_TRUE(privacy_guards_enable_dns_leak_protection(guards, true));
    EXPECT_TRUE(privacy_guards_is_dns_leak_protection_enabled(guards));
    
    // Test IPv6 leak protection
    EXPECT_TRUE(privacy_guards_enable_ipv6_leak_protection(guards, false));
    EXPECT_FALSE(privacy_guards_is_ipv6_leak_protection_enabled(guards));
    EXPECT_TRUE(privacy_guards_enable_ipv6_leak_protection(guards, true));
    EXPECT_TRUE(privacy_guards_is_ipv6_leak_protection_enabled(guards));
    
    // Test WebRTC leak protection
    EXPECT_TRUE(privacy_guards_enable_webrtc_leak_protection(guards, true));
    EXPECT_TRUE(privacy_guards_is_webrtc_leak_protection_enabled(guards));
    EXPECT_TRUE(privacy_guards_enable_webrtc_leak_protection(guards, false));
    EXPECT_FALSE(privacy_guards_is_webrtc_leak_protection_enabled(guards));
    
    // Test kill switch
    EXPECT_TRUE(privacy_guards_enable_kill_switch(guards, false));
    EXPECT_FALSE(privacy_guards_is_kill_switch_enabled(guards));
    EXPECT_FALSE(privacy_guards_is_kill_switch_active(guards));
    EXPECT_TRUE(privacy_guards_enable_kill_switch(guards, true));
    EXPECT_TRUE(privacy_guards_is_kill_switch_enabled(guards));
}

TEST_F(PrivacyGuardsTest, DNSServerManagement) {
    // Test adding DNS server
    ip_addr_t new_dns = { .v4 = { .addr = inet_addr("208.67.222.222") } }; // OpenDNS
    EXPECT_TRUE(privacy_guards_add_allowed_dns_server(guards, &new_dns));
    
    // Test removing DNS server
    EXPECT_TRUE(privacy_guards_remove_allowed_dns_server(guards, &new_dns));
    EXPECT_FALSE(privacy_guards_remove_allowed_dns_server(guards, &new_dns)); // Already removed
    
    // Test removing existing server
    EXPECT_TRUE(privacy_guards_remove_allowed_dns_server(guards, &allowed_dns[1]));
    
    // Re-add for other tests
    EXPECT_TRUE(privacy_guards_add_allowed_dns_server(guards, &allowed_dns[1]));
}

TEST_F(PrivacyGuardsTest, DNSLeakDetection) {
    // Create DNS packet to allowed server (should not be blocked)
    flow_tuple_t allowed_flow = {};
    allowed_flow.ip_version = 4;
    allowed_flow.protocol = PROTO_UDP;
    allowed_flow.src_ip = { .v4 = { .addr = inet_addr("192.168.1.100") } };
    allowed_flow.dst_ip = allowed_dns[0]; // Google DNS
    allowed_flow.src_port = 12345;
    allowed_flow.dst_port = 53;
    
    uint8_t dns_packet[] = {
        0x12, 0x34, 0x01, 0x00,  // DNS header
        0x00, 0x01, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x03, 't', 'e', 's', 't',   // Query for test.com
        0x03, 'c', 'o', 'm', 0x00,
        0x00, 0x01, 0x00, 0x01
    };
    
    bool should_block = false;
    EXPECT_TRUE(privacy_guards_inspect_packet(guards, dns_packet, sizeof(dns_packet), &allowed_flow, &should_block));
    EXPECT_FALSE(should_block);
    EXPECT_EQ(privacy_guards_get_dns_leak_status(guards), DNS_LEAK_STATUS_NONE);
    
    // Create DNS packet to unauthorized server (should be blocked)
    flow_tuple_t unauthorized_flow = allowed_flow;
    unauthorized_flow.dst_ip = { .v4 = { .addr = inet_addr("4.4.4.4") } }; // Unauthorized DNS
    
    EXPECT_TRUE(privacy_guards_inspect_packet(guards, dns_packet, sizeof(dns_packet), &unauthorized_flow, &should_block));
    EXPECT_TRUE(should_block);
    EXPECT_EQ(privacy_guards_get_dns_leak_status(guards), DNS_LEAK_STATUS_KILL_SWITCH_ACTIVE);
    EXPECT_TRUE(privacy_guards_is_kill_switch_active(guards));
}

TEST_F(PrivacyGuardsTest, IPv6LeakDetection) {
    // Create IPv6 packet (should be blocked in IPv4-only VPN)
    flow_tuple_t ipv6_flow = {};
    ipv6_flow.ip_version = 6;
    ipv6_flow.protocol = PROTO_TCP;
    ipv6_flow.src_port = 12345;
    ipv6_flow.dst_port = 80;
    
    uint8_t ipv6_packet[] = {
        0x60, 0x00, 0x00, 0x00,  // IPv6 header
        0x00, 0x00, 0x06, 0x40,
        // Addresses would follow...
    };
    
    bool should_block = false;
    EXPECT_TRUE(privacy_guards_inspect_packet(guards, ipv6_packet, sizeof(ipv6_packet), &ipv6_flow, &should_block));
    EXPECT_TRUE(should_block);
}

TEST_F(PrivacyGuardsTest, WebRTCLeakDetection) {
    // Enable WebRTC protection
    privacy_guards_enable_webrtc_leak_protection(guards, true);
    
    // Create WebRTC STUN packet
    flow_tuple_t webrtc_flow = {};
    webrtc_flow.ip_version = 4;
    webrtc_flow.protocol = PROTO_UDP;
    webrtc_flow.src_ip = { .v4 = { .addr = inet_addr("192.168.1.100") } };
    webrtc_flow.dst_ip = { .v4 = { .addr = inet_addr("74.125.224.127") } }; // Google STUN
    webrtc_flow.src_port = 12345;
    webrtc_flow.dst_port = 3478; // STUN port
    
    uint8_t stun_packet[] = {
        0x00, 0x01, 0x00, 0x00,  // STUN Binding Request
        0x21, 0x12, 0xa4, 0x42,  // Magic cookie
        0x12, 0x34, 0x56, 0x78,  // Transaction ID
        0x9a, 0xbc, 0xde, 0xf0,
        0x12, 0x34, 0x56, 0x78
    };
    
    bool should_block = false;
    EXPECT_TRUE(privacy_guards_inspect_packet(guards, stun_packet, sizeof(stun_packet), &webrtc_flow, &should_block));
    EXPECT_TRUE(should_block);
}

TEST_F(PrivacyGuardsTest, TLSValidation) {
    // Valid TLS 1.3 handshake
    uint8_t tls13_handshake[] = {
        0x16, 0x03, 0x04, 0x00, 0x00  // TLS 1.3 handshake record
    };
    
    EXPECT_TRUE(privacy_guards_validate_tls_connection(guards, tls13_handshake, sizeof(tls13_handshake)));
    
    // Weak TLS 1.0 handshake
    uint8_t tls10_handshake[] = {
        0x16, 0x03, 0x01, 0x00, 0x00  // TLS 1.0 handshake record
    };
    
    EXPECT_FALSE(privacy_guards_validate_tls_connection(guards, tls10_handshake, sizeof(tls10_handshake)));
    
    // Invalid TLS packet
    uint8_t invalid_tls[] = {
        0x15, 0x02, 0x00, 0x00, 0x00  // Invalid record type and version
    };
    
    EXPECT_FALSE(privacy_guards_validate_tls_connection(guards, invalid_tls, sizeof(invalid_tls)));
}

TEST_F(PrivacyGuardsTest, ViolationCallback) {
    std::atomic<int> violation_count{0};
    privacy_violation_t last_violation;
    
    auto callback = [](const privacy_violation_t *violation, void *user_data) {
        auto *count = static_cast<std::atomic<int>*>(user_data);
        count->fetch_add(1);
        
        EXPECT_NE(violation, nullptr);
        EXPECT_GT(violation->timestamp_ns, 0);
        EXPECT_GE(violation->type, PRIVACY_VIOLATION_DNS_LEAK);
    };
    
    privacy_guards_set_violation_callback(guards, callback, &violation_count);
    
    // Trigger DNS leak
    flow_tuple_t leak_flow = {};
    leak_flow.ip_version = 4;
    leak_flow.protocol = PROTO_UDP;
    leak_flow.dst_ip = { .v4 = { .addr = inet_addr("4.4.4.4") } }; // Unauthorized DNS
    leak_flow.dst_port = 53;
    
    uint8_t dns_packet[] = { 0x12, 0x34, 0x01, 0x00 };
    bool should_block;
    
    privacy_guards_inspect_packet(guards, dns_packet, sizeof(dns_packet), &leak_flow, &should_block);
    
    // Give callback time to execute
    std::this_thread::sleep_for(std::chrono::milliseconds(10));
    
    EXPECT_GT(violation_count.load(), 0);
}

TEST_F(PrivacyGuardsTest, MemorySecurity) {
    uint8_t sensitive_data[] = "password123";
    size_t data_size = sizeof(sensitive_data);
    
    // Test secure memory clearing
    privacy_guards_clear_memory(sensitive_data, data_size);
    
    for (size_t i = 0; i < data_size; i++) {
        EXPECT_EQ(sensitive_data[i], 0);
    }
    
    // Test secure zero
    uint8_t more_data[] = "secret_key_data";
    privacy_guards_secure_zero(more_data, sizeof(more_data));
    
    for (size_t i = 0; i < sizeof(more_data); i++) {
        EXPECT_EQ(more_data[i], 0);
    }
}

TEST_F(PrivacyGuardsTest, Statistics) {
    privacy_stats_t stats;
    privacy_guards_get_stats(guards, &stats);
    
    EXPECT_EQ(stats.total_violations, 0);
    EXPECT_EQ(stats.dns_leaks_detected, 0);
    EXPECT_EQ(stats.packets_inspected, 0);
    
    // Trigger some violations to test stats
    flow_tuple_t leak_flow = {};
    leak_flow.ip_version = 4;
    leak_flow.protocol = PROTO_UDP;
    leak_flow.dst_ip = { .v4 = { .addr = inet_addr("4.4.4.4") } };
    leak_flow.dst_port = 53;
    
    uint8_t packet[] = { 0x12, 0x34 };
    bool should_block;
    
    for (int i = 0; i < 5; i++) {
        privacy_guards_inspect_packet(guards, packet, sizeof(packet), &leak_flow, &should_block);
    }
    
    privacy_guards_get_stats(guards, &stats);
    EXPECT_EQ(stats.packets_inspected, 5);
    EXPECT_GT(stats.dns_leaks_detected, 0);
    EXPECT_GT(stats.total_violations, 0);
    
    // Test stats reset
    privacy_guards_reset_stats(guards);
    privacy_guards_get_stats(guards, &stats);
    EXPECT_EQ(stats.packets_inspected, 0);
    EXPECT_EQ(stats.total_violations, 0);
}

TEST_F(PrivacyGuardsTest, ViolationExport) {
    // Trigger some violations
    flow_tuple_t leak_flow = {};
    leak_flow.ip_version = 4;
    leak_flow.protocol = PROTO_UDP;
    leak_flow.dst_ip = { .v4 = { .addr = inet_addr("4.4.4.4") } };
    leak_flow.dst_port = 53;
    
    uint8_t packet[] = { 0x12, 0x34 };
    bool should_block;
    
    for (int i = 0; i < 3; i++) {
        privacy_guards_inspect_packet(guards, packet, sizeof(packet), &leak_flow, &should_block);
    }
    
    // Export violations
    privacy_violation_t violations[10];
    size_t actual_count;
    
    EXPECT_TRUE(privacy_guards_export_violations(guards, violations, 10, &actual_count));
    EXPECT_GT(actual_count, 0);
    EXPECT_LE(actual_count, 3);
    
    // Check violation data
    for (size_t i = 0; i < actual_count; i++) {
        EXPECT_EQ(violations[i].type, PRIVACY_VIOLATION_DNS_LEAK);
        EXPECT_GT(violations[i].timestamp_ns, 0);
        EXPECT_TRUE(violations[i].blocked);
    }
}

TEST_F(PrivacyGuardsTest, ConcurrentInspection) {
    const int num_threads = 4;
    const int packets_per_thread = 50;
    std::atomic<int> total_inspections{0};
    std::vector<std::thread> threads;
    
    auto inspect_packets = [&](int thread_id) {
        flow_tuple_t flow = {};
        flow.ip_version = 4;
        flow.protocol = PROTO_TCP;
        flow.src_port = 1000 + thread_id;
        flow.dst_port = 80;
        
        uint8_t packet[] = { 0x45, 0x00, 0x00, 0x28 }; // IPv4 header start
        
        for (int i = 0; i < packets_per_thread; i++) {
            bool should_block;
            if (privacy_guards_inspect_packet(guards, packet, sizeof(packet), &flow, &should_block)) {
                total_inspections.fetch_add(1);
            }
            
            // Brief delay to allow thread interleaving
            std::this_thread::sleep_for(std::chrono::microseconds(100));
        }
    };
    
    // Start threads
    for (int i = 0; i < num_threads; i++) {
        threads.emplace_back(inspect_packets, i);
    }
    
    // Wait for completion
    for (auto& t : threads) {
        t.join();
    }
    
    EXPECT_EQ(total_inspections.load(), num_threads * packets_per_thread);
    
    privacy_stats_t stats;
    privacy_guards_get_stats(guards, &stats);
    EXPECT_EQ(stats.packets_inspected, num_threads * packets_per_thread);
}

TEST_F(PrivacyGuardsTest, ErrorHandling) {
    // Test null parameters
    EXPECT_FALSE(privacy_guards_enable_dns_leak_protection(nullptr, true));
    EXPECT_FALSE(privacy_guards_is_dns_leak_protection_enabled(nullptr));
    
    EXPECT_FALSE(privacy_guards_add_allowed_dns_server(nullptr, &allowed_dns[0]));
    EXPECT_FALSE(privacy_guards_add_allowed_dns_server(guards, nullptr));
    
    EXPECT_FALSE(privacy_guards_inspect_packet(nullptr, nullptr, 0, nullptr, nullptr));
    
    flow_tuple_t flow = {};
    uint8_t packet[] = { 0x01, 0x02 };
    bool should_block;
    
    EXPECT_FALSE(privacy_guards_inspect_packet(guards, nullptr, 0, &flow, &should_block));
    EXPECT_FALSE(privacy_guards_inspect_packet(guards, packet, 0, nullptr, &should_block));
    EXPECT_FALSE(privacy_guards_inspect_packet(guards, packet, sizeof(packet), &flow, nullptr));
    
    EXPECT_FALSE(privacy_guards_validate_tls_connection(nullptr, packet, sizeof(packet)));
    EXPECT_FALSE(privacy_guards_validate_tls_connection(guards, nullptr, 0));
    
    privacy_guards_get_stats(nullptr, nullptr); // Should not crash
    privacy_guards_reset_stats(nullptr);        // Should not crash
    privacy_guards_destroy(nullptr);            // Should not crash
    
    privacy_guards_clear_memory(nullptr, 0);    // Should not crash
    privacy_guards_secure_zero(nullptr, 0);     // Should not crash
}

TEST_F(PrivacyGuardsTest, StringConversions) {
    EXPECT_STREQ(privacy_violation_type_string(PRIVACY_VIOLATION_DNS_LEAK), "DNS Leak");
    EXPECT_STREQ(privacy_violation_type_string(PRIVACY_VIOLATION_IPV6_LEAK), "IPv6 Leak");
    EXPECT_STREQ(privacy_violation_type_string(PRIVACY_VIOLATION_WEBRTC_LEAK), "WebRTC Leak");
    EXPECT_STREQ(privacy_violation_type_string(PRIVACY_VIOLATION_UNENCRYPTED_DNS), "Unencrypted DNS");
    EXPECT_STREQ(privacy_violation_type_string(PRIVACY_VIOLATION_WEAK_ENCRYPTION), "Weak Encryption");
    
    EXPECT_STREQ(dns_leak_status_string(DNS_LEAK_STATUS_NONE), "None");
    EXPECT_STREQ(dns_leak_status_string(DNS_LEAK_STATUS_DETECTED), "Detected");
    EXPECT_STREQ(dns_leak_status_string(DNS_LEAK_STATUS_BLOCKED), "Blocked");
    EXPECT_STREQ(dns_leak_status_string(DNS_LEAK_STATUS_KILL_SWITCH_ACTIVE), "Kill Switch Active");
}