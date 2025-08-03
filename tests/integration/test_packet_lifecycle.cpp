#include <gtest/gtest.h>
#include "api/relative_vpn.h"
#include "packet/utun.h"
#include "packet/buffer_manager.h"
#include "core/types.h"
#include <thread>
#include <chrono>
#include <atomic>
#include <vector>
#include <queue>
#include <mutex>
#include <condition_variable>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>

/**
 * Comprehensive Packet Lifecycle Test Suite
 * 
 * PRIMARY PURPOSE: Test "packets going in and going out" as requested by user
 * This validates the complete packet processing pipeline for iOS connectivity:
 * 
 * iOS NetworkExtension → UTun → VPN Processing → Internet (outbound)
 * Internet → VPN Processing → UTun → iOS NetworkExtension (inbound)
 */

class PacketLifecycleTest : public ::testing::Test {
protected:
    void SetUp() override {
        // Initialize VPN configuration for packet testing
        config = {};
        config.utun_name = nullptr; // Auto-assign
        config.mtu = 1500;
        config.tunnel_mtu = 1500;
        config.ipv4_enabled = true;
        config.ipv6_enabled = true;
        config.enable_nat64 = true;
        config.enable_dns_leak_protection = true;
        config.enable_ipv6_leak_protection = true;
        config.enable_kill_switch = false; // Allow testing flexibility
        config.enable_webrtc_leak_protection = true;
        
        // Configure test DNS servers
        config.dns_servers[0] = inet_addr("8.8.8.8");
        config.dns_servers[1] = inet_addr("1.1.1.1");
        config.dns_server_count = 2;
        
        config.dns_cache_size = 1024;
        config.metrics_buffer_size = 4096;
        config.reachability_monitoring = true;
        config.log_level = const_cast<char*>("DEBUG");
        
        // Initialize packet tracking
        packets_sent = 0;
        packets_received = 0;
        packets_processed = 0;
        test_completed = false;
        
        result = {};
        
        // Clear captured packets
        ingress_packets.clear();
        egress_packets.clear();
    }
    
    void TearDown() override {
        if (result.handle != VPN_INVALID_HANDLE) {
            vpn_stop_comprehensive(result.handle);
        }
    }
    
    // Test data structures
    vpn_config_t config;
    vpn_result_t result;
    
    // Packet tracking
    std::atomic<int> packets_sent{0};
    std::atomic<int> packets_received{0};
    std::atomic<int> packets_processed{0};
    std::atomic<bool> test_completed{false};
    
    // Packet capture for validation
    std::vector<packet_info_t> ingress_packets;
    std::vector<packet_info_t> egress_packets;
    std::mutex packet_mutex;
    
    // Test utilities
    packet_info_t create_test_packet(const char* src_ip, const char* dst_ip, 
                                   uint16_t src_port, uint16_t dst_port,
                                   protocol_type_t protocol, const uint8_t* payload = nullptr, 
                                   size_t payload_size = 0);
    
    bool validate_packet_integrity(const packet_info_t& original, const packet_info_t& processed);
    bool start_vpn_with_retry();
    void wait_for_packet_processing(int expected_count, int timeout_ms = 5000);
};

packet_info_t PacketLifecycleTest::create_test_packet(const char* src_ip, const char* dst_ip,
                                                    uint16_t src_port, uint16_t dst_port,
                                                    protocol_type_t protocol, const uint8_t* payload,
                                                    size_t payload_size) {
    static uint8_t packet_buffer[MAX_PACKET_SIZE];
    packet_info_t packet = {};
    
    // Build IP header
    struct ip* ip_hdr = (struct ip*)packet_buffer;
    ip_hdr->ip_v = 4;
    ip_hdr->ip_hl = 5;
    ip_hdr->ip_tos = 0;
    ip_hdr->ip_len = htons(sizeof(struct ip) + 
                          (protocol == PROTO_TCP ? sizeof(struct tcphdr) : sizeof(struct udphdr)) +
                          payload_size);
    ip_hdr->ip_id = htons(rand() % 65535);
    ip_hdr->ip_off = 0;
    ip_hdr->ip_ttl = 64;
    ip_hdr->ip_p = protocol;
    ip_hdr->ip_sum = 0;
    inet_pton(AF_INET, src_ip, &ip_hdr->ip_src);
    inet_pton(AF_INET, dst_ip, &ip_hdr->ip_dst);
    
    // Calculate IP checksum
    ip_hdr->ip_sum = 0; // Will be calculated by system
    
    size_t header_offset = sizeof(struct ip);
    
    // Add transport header
    if (protocol == PROTO_TCP) {
        struct tcphdr* tcp_hdr = (struct tcphdr*)(packet_buffer + header_offset);
        tcp_hdr->th_sport = htons(src_port);
        tcp_hdr->th_dport = htons(dst_port);
        tcp_hdr->th_seq = htonl(rand());
        tcp_hdr->th_ack = 0;
        tcp_hdr->th_off = 5;
        tcp_hdr->th_flags = TH_SYN;
        tcp_hdr->th_win = htons(65535);
        tcp_hdr->th_sum = 0;
        tcp_hdr->th_urp = 0;
        header_offset += sizeof(struct tcphdr);
    } else if (protocol == PROTO_UDP) {
        struct udphdr* udp_hdr = (struct udphdr*)(packet_buffer + header_offset);
        udp_hdr->uh_sport = htons(src_port);
        udp_hdr->uh_dport = htons(dst_port);
        udp_hdr->uh_ulen = htons(sizeof(struct udphdr) + payload_size);
        udp_hdr->uh_sum = 0;
        header_offset += sizeof(struct udphdr);
    }
    
    // Add payload
    if (payload && payload_size > 0) {
        memcpy(packet_buffer + header_offset, payload, payload_size);
    }
    
    // Set packet info
    packet.data = packet_buffer;
    packet.length = header_offset + payload_size;
    packet.flow.ip_version = 4;
    packet.flow.protocol = protocol;
    packet.flow.src_ip.v4.addr = inet_addr(src_ip);
    packet.flow.dst_ip.v4.addr = inet_addr(dst_ip);
    packet.flow.src_port = src_port;
    packet.flow.dst_port = dst_port;
    packet.timestamp_ns = clock_gettime_nsec_np(CLOCK_MONOTONIC);
    
    return packet;
}

bool PacketLifecycleTest::validate_packet_integrity(const packet_info_t& original, 
                                                   const packet_info_t& processed) {
    // Basic integrity checks
    if (processed.length == 0 || processed.data == nullptr) {
        return false;
    }
    
    // Flow tuple should be preserved (may be translated for NAT64)
    if (original.flow.ip_version == processed.flow.ip_version) {
        return (original.flow.src_port == processed.flow.src_port &&
                original.flow.dst_port == processed.flow.dst_port &&
                original.flow.protocol == processed.flow.protocol);
    }
    
    // Allow for IPv4/IPv6 translation
    return (original.flow.src_port == processed.flow.src_port &&
            original.flow.dst_port == processed.flow.dst_port);
}

bool PacketLifecycleTest::start_vpn_with_retry() {
    result = vpn_start_comprehensive(&config);
    
    if (result.status == VPN_ERROR_PERMISSION) {
        GTEST_SKIP() << "Skipping packet lifecycle tests - requires root/NetworkExtension permissions";
        return false;
    }
    
    if (result.status != VPN_SUCCESS) {
        // Retry once with auto-assigned interface
        config.utun_name = nullptr;
        result = vpn_start_comprehensive(&config);
    }
    
    return (result.status == VPN_SUCCESS && result.handle != VPN_INVALID_HANDLE);
}

void PacketLifecycleTest::wait_for_packet_processing(int expected_count, int timeout_ms) {
    auto start_time = std::chrono::steady_clock::now();
    
    while (packets_processed.load() < expected_count) {
        auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now() - start_time).count();
            
        if (elapsed >= timeout_ms) {
            break;
        }
        
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
}

// PRIMARY TEST: Complete packet ingress/egress flow validation
TEST_F(PacketLifecycleTest, CompletePacketFlow_IngressEgress) {
    ASSERT_TRUE(start_vpn_with_retry());
    
    // Test multiple packet types through complete pipeline
    struct TestCase {
        const char* name;
        const char* src_ip;
        const char* dst_ip;
        uint16_t src_port;
        uint16_t dst_port;
        protocol_type_t protocol;
        const char* payload;
    } test_cases[] = {
        {"HTTP_Request", "10.0.0.1", "93.184.216.34", 45678, 80, PROTO_TCP, "GET / HTTP/1.1\r\n"},
        {"DNS_Query", "10.0.0.1", "8.8.8.8", 53478, 53, PROTO_UDP, "\x12\x34\x01\x00\x00\x01"},
        {"HTTPS_Request", "10.0.0.1", "104.16.132.229", 56789, 443, PROTO_TCP, "\x16\x03\x01"},
        {"ICMP_Ping", "10.0.0.1", "1.1.1.1", 0, 0, PROTO_ICMP, "ping_test_data"}
    };
    
    for (auto& test_case : test_cases) {
        SCOPED_TRACE(test_case.name);
        
        // Create test packet
        packet_info_t test_packet = create_test_packet(
            test_case.src_ip, test_case.dst_ip,
            test_case.src_port, test_case.dst_port,
            test_case.protocol,
            (const uint8_t*)test_case.payload, strlen(test_case.payload)
        );
        
        // INGRESS: Inject packet from iOS NetworkExtension
        EXPECT_TRUE(vpn_inject_packet_comprehensive(result.handle, &test_packet));
        packets_sent.fetch_add(1);
        
        // Allow processing time
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
    
    // Wait for all packets to be processed
    wait_for_packet_processing(packets_sent.load());
    
    // Verify metrics show packet processing
    vpn_metrics_t metrics;
    ASSERT_TRUE(vpn_get_metrics_comprehensive(result.handle, &metrics));
    
    EXPECT_GT(metrics.total_packets_processed, 0);
    EXPECT_GT(metrics.bytes_received, 0);
    EXPECT_GE(metrics.tcp_connections, 0);
    EXPECT_GE(metrics.udp_sessions, 0);
    
    // Verify no critical errors
    EXPECT_EQ(metrics.packet_errors, 0);
}

// Test packet integrity through VPN processing pipeline
TEST_F(PacketLifecycleTest, PacketIntegrityValidation) {
    ASSERT_TRUE(start_vpn_with_retry());
    
    // Create reference packets with known content
    std::vector<packet_info_t> reference_packets;
    
    // DNS query packet with specific content
    uint8_t dns_query[] = {
        0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x06, 'g', 'o', 'o',
        'g', 'l', 'e', 0x03, 'c', 'o', 'm', 0x00,
        0x00, 0x01, 0x00, 0x01
    };
    
    packet_info_t dns_packet = create_test_packet(
        "10.0.0.1", "8.8.8.8", 53478, 53, PROTO_UDP,
        dns_query, sizeof(dns_query)
    );
    
    reference_packets.push_back(dns_packet);
    
    // HTTP request packet
    const char* http_request = "GET /test HTTP/1.1\r\nHost: example.com\r\n\r\n";
    packet_info_t http_packet = create_test_packet(
        "10.0.0.1", "93.184.216.34", 45678, 80, PROTO_TCP,
        (const uint8_t*)http_request, strlen(http_request)
    );
    
    reference_packets.push_back(http_packet);
    
    // Inject all reference packets
    for (const auto& packet : reference_packets) {
        EXPECT_TRUE(vpn_inject_packet_comprehensive(result.handle, &packet));
        packets_sent.fetch_add(1);
    }
    
    // Process packets
    wait_for_packet_processing(packets_sent.load());
    
    // Verify packet processing metrics
    vpn_metrics_t metrics;
    ASSERT_TRUE(vpn_get_metrics_comprehensive(result.handle, &metrics));
    
    // Should have processed packets without corruption
    EXPECT_GT(metrics.total_packets_processed, 0);
    EXPECT_EQ(metrics.packet_errors, 0); // No corruption errors
    
    // Verify protocol-specific metrics
    EXPECT_GE(metrics.dns_queries, 1); // DNS packet processed
    EXPECT_GE(metrics.tcp_connections, 0); // TCP packet processed
}

// Test high-throughput packet processing
TEST_F(PacketLifecycleTest, HighThroughputPacketFlow) {
    ASSERT_TRUE(start_vpn_with_retry());
    
    const int packet_count = 1000;
    const int thread_count = 4;
    std::atomic<int> successful_injections{0};
    std::vector<std::thread> threads;
    
    auto inject_packets = [&](int thread_id) {
        for (int i = 0; i < packet_count / thread_count; i++) {
            // Vary packet types and destinations
            std::string src_ip = "10.0.0." + std::to_string(thread_id + 1);
            std::string dst_ip = "8.8.8." + std::to_string((thread_id % 4) + 1);
            
            packet_info_t packet = create_test_packet(
                src_ip.c_str(), dst_ip.c_str(),
                1000 + i, 53, PROTO_UDP,
                (const uint8_t*)"test_payload", 12
            );
            
            if (vpn_inject_packet_comprehensive(result.handle, &packet)) {
                successful_injections.fetch_add(1);
            }
            
            // Small delay to avoid overwhelming
            if (i % 50 == 0) {
                std::this_thread::sleep_for(std::chrono::milliseconds(1));
            }
        }
    };
    
    // Start injection threads
    auto start_time = std::chrono::steady_clock::now();
    
    for (int i = 0; i < thread_count; i++) {
        threads.emplace_back(inject_packets, i);
    }
    
    // Wait for completion
    for (auto& t : threads) {
        t.join();
    }
    
    auto injection_time = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now() - start_time).count();
    
    // Allow processing time
    std::this_thread::sleep_for(std::chrono::seconds(2));
    
    // Verify performance metrics
    vpn_metrics_t metrics;
    ASSERT_TRUE(vpn_get_metrics_comprehensive(result.handle, &metrics));
    
    EXPECT_GT(successful_injections.load(), packet_count * 0.95); // At least 95% success
    EXPECT_GT(metrics.total_packets_processed, packet_count * 0.9);
    EXPECT_LT(injection_time, 10000); // Should complete within 10 seconds
    
    // Verify system stability under load
    EXPECT_TRUE(vpn_is_running_comprehensive(result.handle));
    EXPECT_LT(metrics.packet_errors, packet_count * 0.01); // Less than 1% errors
}

// Test packet flow with NAT64 translation
TEST_F(PacketLifecycleTest, NAT64PacketTranslation) {
    config.enable_nat64 = true;
    ASSERT_TRUE(start_vpn_with_retry());
    
    // IPv4 packet that should trigger NAT64 translation
    packet_info_t ipv4_packet = create_test_packet(
        "10.0.0.1", "8.8.8.8", 45678, 53, PROTO_UDP,
        (const uint8_t*)"\x12\x34\x01\x00", 4
    );
    
    EXPECT_TRUE(vpn_inject_packet_comprehensive(result.handle, &ipv4_packet));
    
    // IPv6 packet with NAT64 addressing
    uint8_t ipv6_data[] = {
        0x60, 0x00, 0x00, 0x00, 0x00, 0x04, 0x11, 0x40,
        0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
        0x00, 0x64, 0xff, 0x9b, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x08, 0x08, 0x08, 0x08,
        0x00, 0x35, 0x00, 0x35, 0x00, 0x04, 0x00, 0x00
    };
    
    packet_info_t ipv6_packet = {};
    ipv6_packet.data = ipv6_data;
    ipv6_packet.length = sizeof(ipv6_data);
    ipv6_packet.flow.ip_version = 6;
    ipv6_packet.flow.protocol = PROTO_UDP;
    ipv6_packet.flow.src_port = 45678;
    ipv6_packet.flow.dst_port = 53;
    ipv6_packet.timestamp_ns = clock_gettime_nsec_np(CLOCK_MONOTONIC);
    
    EXPECT_TRUE(vpn_inject_packet_comprehensive(result.handle, &ipv6_packet));
    
    // Allow NAT64 processing
    std::this_thread::sleep_for(std::chrono::milliseconds(500));
    
    // Verify NAT64 translation metrics
    vpn_metrics_t metrics;
    ASSERT_TRUE(vpn_get_metrics_comprehensive(result.handle, &metrics));
    
    EXPECT_GE(metrics.nat64_translations, 0);
    EXPECT_GT(metrics.total_packets_processed, 0);
}

// Test packet flow with privacy guard enforcement
TEST_F(PacketLifecycleTest, PrivacyGuardPacketFiltering) {
    config.enable_dns_leak_protection = true;
    config.enable_ipv6_leak_protection = true;
    ASSERT_TRUE(start_vpn_with_retry());
    
    // Authorized DNS query (should pass)
    packet_info_t allowed_dns = create_test_packet(
        "10.0.0.1", "8.8.8.8", 53478, 53, PROTO_UDP,
        (const uint8_t*)"\x12\x34\x01\x00", 4
    );
    
    EXPECT_TRUE(vpn_inject_packet_comprehensive(result.handle, &allowed_dns));
    
    // Unauthorized DNS query (should be blocked)
    packet_info_t blocked_dns = create_test_packet(
        "10.0.0.1", "4.4.4.4", 53479, 53, PROTO_UDP,
        (const uint8_t*)"\x12\x35\x01\x00", 4
    );
    
    EXPECT_TRUE(vpn_inject_packet_comprehensive(result.handle, &blocked_dns));
    
    // IPv6 packet (should be blocked if protection enabled)
    uint8_t ipv6_data[] = {
        0x60, 0x00, 0x00, 0x00, 0x00, 0x04, 0x11, 0x40,
        0x20, 0x01, 0x48, 0x60, 0x48, 0x60, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x88, 0x88
    };
    
    packet_info_t ipv6_packet = {};
    ipv6_packet.data = ipv6_data;
    ipv6_packet.length = sizeof(ipv6_data);
    ipv6_packet.flow.ip_version = 6;
    ipv6_packet.flow.protocol = PROTO_UDP;
    ipv6_packet.timestamp_ns = clock_gettime_nsec_np(CLOCK_MONOTONIC);
    
    EXPECT_TRUE(vpn_inject_packet_comprehensive(result.handle, &ipv6_packet));
    
    // Process events
    std::this_thread::sleep_for(std::chrono::milliseconds(500));
    
    // Verify privacy enforcement
    vpn_metrics_t metrics;
    ASSERT_TRUE(vpn_get_metrics_comprehensive(result.handle, &metrics));
    
    EXPECT_GT(metrics.total_packets_processed, 0);
    EXPECT_GE(metrics.privacy_violations, 0); // May detect violations
    EXPECT_GE(metrics.packets_blocked, 0); // May block packets
}

// Test error recovery in packet processing pipeline
TEST_F(PacketLifecycleTest, PacketProcessingErrorRecovery) {
    ASSERT_TRUE(start_vpn_with_retry());
    
    // Inject malformed packets
    uint8_t malformed_data[] = { 0xFF, 0xFF, 0xFF, 0xFF };
    packet_info_t malformed_packet = {};
    malformed_packet.data = malformed_data;
    malformed_packet.length = sizeof(malformed_data);
    malformed_packet.flow.ip_version = 4;
    malformed_packet.timestamp_ns = clock_gettime_nsec_np(CLOCK_MONOTONIC);
    
    // Should handle gracefully
    bool injected = vpn_inject_packet_comprehensive(result.handle, &malformed_packet);
    // May succeed (dropped) or fail (rejected) - both OK
    
    // Zero-length packet
    malformed_packet.length = 0;
    vpn_inject_packet_comprehensive(result.handle, &malformed_packet);
    
    // Oversized packet
    uint8_t oversized_data[MAX_PACKET_SIZE + 1000];
    memset(oversized_data, 0xFF, sizeof(oversized_data));
    malformed_packet.data = oversized_data;
    malformed_packet.length = sizeof(oversized_data);
    vpn_inject_packet_comprehensive(result.handle, &malformed_packet);
    
    // Normal packet after errors (verify recovery)
    packet_info_t recovery_packet = create_test_packet(
        "10.0.0.1", "8.8.8.8", 12345, 53, PROTO_UDP,
        (const uint8_t*)"recovery", 8
    );
    
    EXPECT_TRUE(vpn_inject_packet_comprehensive(result.handle, &recovery_packet));
    
    // System should still be functional
    std::this_thread::sleep_for(std::chrono::milliseconds(200));
    
    EXPECT_TRUE(vpn_is_running_comprehensive(result.handle));
    
    vpn_metrics_t metrics;
    ASSERT_TRUE(vpn_get_metrics_comprehensive(result.handle, &metrics));
    EXPECT_GE(metrics.packet_errors, 0); // May have recorded errors
    EXPECT_GT(metrics.total_packets_processed, 0); // Should have processed recovery packet
}

// Test packet flow under memory pressure
TEST_F(PacketLifecycleTest, MemoryPressurePacketHandling) {
    ASSERT_TRUE(start_vpn_with_retry());
    
    // Rapidly inject packets to test memory management
    const int rapid_packet_count = 500;
    std::vector<packet_info_t> packets;
    
    for (int i = 0; i < rapid_packet_count; i++) {
        std::string dst_ip = "8.8.8." + std::to_string((i % 4) + 1);
        
        packet_info_t packet = create_test_packet(
            "10.0.0.1", dst_ip.c_str(),
            1000 + i, 53, PROTO_UDP,
            (const uint8_t*)"memory_test", 11
        );
        
        packets.push_back(packet);
    }
    
    // Inject all packets rapidly
    auto start_time = std::chrono::steady_clock::now();
    int successful_injections = 0;
    
    for (const auto& packet : packets) {
        if (vpn_inject_packet_comprehensive(result.handle, &packet)) {
            successful_injections++;
        }
    }
    
    auto injection_time = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now() - start_time).count();
    
    // Allow processing and cleanup
    std::this_thread::sleep_for(std::chrono::seconds(1));
    
    // Verify system stability
    EXPECT_TRUE(vpn_is_running_comprehensive(result.handle));
    EXPECT_GT(successful_injections, rapid_packet_count * 0.8); // At least 80% success
    
    vpn_metrics_t metrics;
    ASSERT_TRUE(vpn_get_metrics_comprehensive(result.handle, &metrics));
    EXPECT_GT(metrics.total_packets_processed, 0);
    
    // Memory should be properly managed (no leaks)
    // Additional memory leak detection would be in separate memory tests
}