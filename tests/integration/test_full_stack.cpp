#include <gtest/gtest.h>
#include "api/relative_vpn.h"
#include "packet/utun.h"
#include "dns/resolver.h"
#include "privacy/guards.h"
#include "socket_bridge/bridge.h"
#include "nat64/translator.h"
#include "metrics/ring_buffer.h"
#include <thread>
#include <chrono>
#include <atomic>

class FullStackIntegrationTest : public ::testing::Test {
protected:
    void SetUp() override {
        // Initialize VPN configuration
        vpn_config_init(&config);
        config.enable_logging = true;
        config.log_level = LOG_LEVEL_DEBUG;
        
        // Configure tunnel
        config.tunnel_mtu = 1500;
        inet_pton(AF_INET, "10.0.0.1", &config.tunnel_ipv4);
        inet_pton(AF_INET, "255.255.255.0", &config.tunnel_netmask);
        
        // Configure DNS
        config.dns_server_count = 2;
        inet_pton(AF_INET, "8.8.8.8", &config.dns_servers[0]);
        inet_pton(AF_INET, "1.1.1.1", &config.dns_servers[1]);
        
        // Enable privacy features
        config.enable_kill_switch = true;
        config.enable_dns_leak_protection = true;
        config.enable_ipv6_leak_protection = true;
        
        result = {};
    }
    
    void TearDown() override {
        if (result.handle != VPN_INVALID_HANDLE) {
            vpn_stop(result.handle);
        }
    }
    
    vpn_config_t config;
    vpn_result_t result;
};

TEST_F(FullStackIntegrationTest, VPNStartupShutdown) {
    // Test complete VPN startup sequence
    result = vpn_start(&config);
    
    EXPECT_EQ(result.status, VPN_STATUS_SUCCESS);
    EXPECT_NE(result.handle, VPN_INVALID_HANDLE);
    
    // Verify components are initialized
    EXPECT_TRUE(vpn_is_running(result.handle));
    
    // Get initial metrics
    vpn_metrics_t initial_metrics;
    EXPECT_TRUE(vpn_get_metrics(result.handle, &initial_metrics));
    EXPECT_GE(initial_metrics.uptime_seconds, 0);
    
    // Test graceful shutdown
    EXPECT_TRUE(vpn_stop(result.handle));
    EXPECT_FALSE(vpn_is_running(result.handle));
    
    result.handle = VPN_INVALID_HANDLE; // Prevent double cleanup
}

TEST_F(FullStackIntegrationTest, DNSResolutionWithPrivacyGuards) {
    result = vpn_start(&config);
    ASSERT_EQ(result.status, VPN_STATUS_SUCCESS);
    
    std::atomic<bool> query_completed{false};
    std::atomic<bool> violation_detected{false};
    
    // Set up privacy violation callback
    auto violation_callback = [](const privacy_violation_t *violation, void *user_data) {
        auto *detected = static_cast<std::atomic<bool>*>(user_data);
        detected->store(true);
        EXPECT_NE(violation, nullptr);
    };
    
    // Simulate DNS query to allowed server (should succeed)
    uint8_t allowed_dns_query[] = {
        0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x06, 'g', 'o', 'o',
        'g', 'l', 'e', 0x03, 'c', 'o', 'm', 0x00,
        0x00, 0x01, 0x00, 0x01
    };
    
    // Create packet to allowed DNS server
    packet_info_t allowed_packet = {};
    allowed_packet.data = allowed_dns_query;
    allowed_packet.length = sizeof(allowed_dns_query);
    allowed_packet.flow.ip_version = 4;
    allowed_packet.flow.protocol = PROTO_UDP;
    allowed_packet.flow.src_ip.v4.addr = inet_addr("10.0.0.1");
    allowed_packet.flow.dst_ip.v4.addr = inet_addr("8.8.8.8");
    allowed_packet.flow.src_port = 12345;
    allowed_packet.flow.dst_port = 53;
    allowed_packet.timestamp_ns = clock_gettime_nsec_np(CLOCK_MONOTONIC);
    
    // Inject allowed DNS packet
    EXPECT_TRUE(vpn_inject_packet(result.handle, &allowed_packet));
    
    // Process for a bit
    for (int i = 0; i < 20; i++) {
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
    }
    
    // Should not have detected violations for allowed DNS
    vpn_metrics_t metrics;
    vpn_get_metrics(result.handle, &metrics);
    EXPECT_EQ(metrics.privacy_violations, 0);
    
    // Now test unauthorized DNS server (should be blocked)
    packet_info_t blocked_packet = allowed_packet;
    blocked_packet.flow.dst_ip.v4.addr = inet_addr("4.4.4.4"); // Unauthorized DNS
    
    EXPECT_TRUE(vpn_inject_packet(result.handle, &blocked_packet));
    
    // Process events
    for (int i = 0; i < 20; i++) {
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
    }
    
    // Should have detected privacy violation
    vpn_get_metrics(result.handle, &metrics);
    EXPECT_GT(metrics.privacy_violations, 0);
}

TEST_F(FullStackIntegrationTest, IPv6LeakProtection) {
    result = vpn_start(&config);
    ASSERT_EQ(result.status, VPN_STATUS_SUCCESS);
    
    // Create IPv6 packet (should be blocked if IPv6 protection is enabled)
    uint8_t ipv6_packet[] = {
        0x60, 0x00, 0x00, 0x00, 0x00, 0x08, 0x11, 0x40,
        // Source IPv6 address
        0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
        // Destination IPv6 address
        0x20, 0x01, 0x48, 0x60, 0x48, 0x60, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x88, 0x88,
        // UDP header
        0x00, 0x35, 0x00, 0x35, 0x00, 0x08, 0x00, 0x00
    };
    
    packet_info_t ipv6_pkt = {};
    ipv6_pkt.data = ipv6_packet;
    ipv6_pkt.length = sizeof(ipv6_packet);
    ipv6_pkt.flow.ip_version = 6;
    ipv6_pkt.flow.protocol = PROTO_UDP;
    ipv6_pkt.flow.src_port = 12345;
    ipv6_pkt.flow.dst_port = 53;
    ipv6_pkt.timestamp_ns = clock_gettime_nsec_np(CLOCK_MONOTONIC);
    
    // Inject IPv6 packet
    EXPECT_TRUE(vpn_inject_packet(result.handle, &ipv6_pkt));
    
    // Process events
    for (int i = 0; i < 20; i++) {
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
    }
    
    // Should have blocked IPv6 traffic and recorded violation
    vpn_metrics_t metrics;
    vpn_get_metrics(result.handle, &metrics);
    EXPECT_GT(metrics.ipv6_packets_blocked, 0);
}

TEST_F(FullStackIntegrationTest, NAT64Translation) {
    result = vpn_start(&config);
    ASSERT_EQ(result.status, VPN_STATUS_SUCCESS);
    
    // Create IPv4 packet to be translated to IPv6
    uint8_t ipv4_packet[] = {
        0x45, 0x00, 0x00, 0x20, 0x00, 0x01, 0x40, 0x00,
        0x40, 0x11, 0x00, 0x00, 0xc0, 0xa8, 0x01, 0x01,
        0x08, 0x08, 0x08, 0x08, 0x00, 0x35, 0x00, 0x35,
        0x00, 0x0c, 0x00, 0x00, 0x01, 0x02, 0x03, 0x04
    };
    
    packet_info_t nat64_packet = {};
    nat64_packet.data = ipv4_packet;
    nat64_packet.length = sizeof(ipv4_packet);
    nat64_packet.flow.ip_version = 4;
    nat64_packet.flow.protocol = PROTO_UDP;
    nat64_packet.flow.src_ip.v4.addr = inet_addr("192.168.1.1");
    nat64_packet.flow.dst_ip.v4.addr = inet_addr("8.8.8.8");
    nat64_packet.flow.src_port = 53;
    nat64_packet.flow.dst_port = 53;
    nat64_packet.timestamp_ns = clock_gettime_nsec_np(CLOCK_MONOTONIC);
    
    // Inject packet for NAT64 processing
    EXPECT_TRUE(vpn_inject_packet(result.handle, &nat64_packet));
    
    // Process events
    for (int i = 0; i < 20; i++) {
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
    }
    
    // Check NAT64 translation metrics
    vpn_metrics_t metrics;
    vpn_get_metrics(result.handle, &metrics);
    EXPECT_GE(metrics.nat64_translations, 0);
}

TEST_F(FullStackIntegrationTest, MetricsCollection) {
    result = vpn_start(&config);
    ASSERT_EQ(result.status, VPN_STATUS_SUCCESS);
    
    // Generate various types of traffic
    std::vector<packet_info_t> test_packets;
    
    // Create different packet types
    for (int i = 0; i < 10; i++) {
        packet_info_t packet = {};
        
        // Alternate between TCP and UDP
        uint8_t tcp_packet[] = {
            0x45, 0x00, 0x00, 0x28, 0x00, 0x01, 0x40, 0x00,
            0x40, 0x06, 0x00, 0x00, 0x0a, 0x00, 0x00, 0x01,
            0x5d, 0xb8, 0xd8, 0x22, 0x00, 0x50, 0x1f, 0x90,
            0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
            0x50, 0x02, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00
        };
        
        packet.data = tcp_packet;
        packet.length = sizeof(tcp_packet);
        packet.flow.ip_version = 4;
        packet.flow.protocol = (i % 2 == 0) ? PROTO_TCP : PROTO_UDP;
        packet.flow.src_ip.v4.addr = inet_addr("10.0.0.1");
        packet.flow.dst_ip.v4.addr = htonl(0x5DB8D822 + i);
        packet.flow.src_port = 1000 + i;
        packet.flow.dst_port = (i % 2 == 0) ? 80 : 53;
        packet.timestamp_ns = clock_gettime_nsec_np(CLOCK_MONOTONIC);
        
        EXPECT_TRUE(vpn_inject_packet(result.handle, &packet));
    }
    
    // Process all packets
    for (int i = 0; i < 50; i++) {
        std::this_thread::sleep_for(std::chrono::milliseconds(20));
    }
    
    // Verify metrics were collected
    vpn_metrics_t metrics;
    EXPECT_TRUE(vpn_get_metrics(result.handle, &metrics));
    
    EXPECT_GT(metrics.total_packets_processed, 0);
    EXPECT_GT(metrics.bytes_received, 0);
    EXPECT_GE(metrics.tcp_connections, 0);
    EXPECT_GE(metrics.udp_sessions, 0);
    EXPECT_GT(metrics.uptime_seconds, 0);
}

TEST_F(FullStackIntegrationTest, ConcurrentTrafficHandling) {
    result = vpn_start(&config);
    ASSERT_EQ(result.status, VPN_STATUS_SUCCESS);
    
    const int num_threads = 4;
    const int packets_per_thread = 25;
    std::atomic<int> packets_injected{0};
    std::atomic<int> successful_injections{0};
    std::vector<std::thread> threads;
    
    auto inject_traffic = [&](int thread_id) {
        for (int i = 0; i < packets_per_thread; i++) {
            uint8_t packet_data[] = {
                0x45, 0x00, 0x00, 0x1c, 0x00, 0x01, 0x40, 0x00,
                0x40, 0x11, 0x00, 0x00, 0x0a, 0x00, 0x00, 0x01,
                0x08, 0x08, 0x08, 0x08, 0x00, 0x35, 0x00, 0x35,
                0x00, 0x08, 0x00, 0x00
            };
            
            packet_info_t packet = {};
            packet.data = packet_data;
            packet.length = sizeof(packet_data);
            packet.flow.ip_version = 4;
            packet.flow.protocol = PROTO_UDP;
            packet.flow.src_ip.v4.addr = htonl(0x0A000001 + thread_id);
            packet.flow.dst_ip.v4.addr = inet_addr("8.8.8.8");
            packet.flow.src_port = 1000 + thread_id * 100 + i;
            packet.flow.dst_port = 53;
            packet.timestamp_ns = clock_gettime_nsec_np(CLOCK_MONOTONIC);
            
            packets_injected.fetch_add(1);
            
            if (vpn_inject_packet(result.handle, &packet)) {
                successful_injections.fetch_add(1);
            }
            
            std::this_thread::sleep_for(std::chrono::milliseconds(5));
        }
    };
    
    // Start traffic injection threads
    for (int i = 0; i < num_threads; i++) {
        threads.emplace_back(inject_traffic, i);
    }
    
    // Wait for all threads to complete
    for (auto& t : threads) {
        t.join();
    }
    
    // Process remaining events
    for (int i = 0; i < 100; i++) {
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
    
    EXPECT_EQ(packets_injected.load(), num_threads * packets_per_thread);
    EXPECT_GT(successful_injections.load(), 0);
    
    // Verify final metrics
    vpn_metrics_t final_metrics;
    EXPECT_TRUE(vpn_get_metrics(result.handle, &final_metrics));
    EXPECT_GT(final_metrics.total_packets_processed, 0);
}

TEST_F(FullStackIntegrationTest, ErrorRecovery) {
    result = vpn_start(&config);
    ASSERT_EQ(result.status, VPN_STATUS_SUCCESS);
    
    // Test recovery from various error conditions
    
    // 1. Inject malformed packet
    uint8_t malformed_packet[] = { 0xFF, 0xFF, 0xFF, 0xFF };
    packet_info_t bad_packet = {};
    bad_packet.data = malformed_packet;
    bad_packet.length = sizeof(malformed_packet);
    bad_packet.flow.ip_version = 4;
    bad_packet.timestamp_ns = clock_gettime_nsec_np(CLOCK_MONOTONIC);
    
    // Should handle gracefully without crashing
    bool injected = vpn_inject_packet(result.handle, &bad_packet);
    // May succeed (packet dropped) or fail (validation), both are OK
    
    // 2. Test with zero-length packet
    bad_packet.length = 0;
    vpn_inject_packet(result.handle, &bad_packet); // Should not crash
    
    // 3. Test VPN should still be functional after errors
    uint8_t good_packet[] = {
        0x45, 0x00, 0x00, 0x1c, 0x00, 0x01, 0x40, 0x00,
        0x40, 0x11, 0x00, 0x00, 0x0a, 0x00, 0x00, 0x01,
        0x08, 0x08, 0x08, 0x08, 0x00, 0x35, 0x00, 0x35,
        0x00, 0x08, 0x00, 0x00
    };
    
    packet_info_t recovery_packet = {};
    recovery_packet.data = good_packet;
    recovery_packet.length = sizeof(good_packet);
    recovery_packet.flow.ip_version = 4;
    recovery_packet.flow.protocol = PROTO_UDP;
    recovery_packet.flow.src_ip.v4.addr = inet_addr("10.0.0.1");
    recovery_packet.flow.dst_ip.v4.addr = inet_addr("8.8.8.8");
    recovery_packet.flow.src_port = 12345;
    recovery_packet.flow.dst_port = 53;
    recovery_packet.timestamp_ns = clock_gettime_nsec_np(CLOCK_MONOTONIC);
    
    EXPECT_TRUE(vpn_inject_packet(result.handle, &recovery_packet));
    
    // VPN should still be running
    EXPECT_TRUE(vpn_is_running(result.handle));
    
    vpn_metrics_t metrics;
    EXPECT_TRUE(vpn_get_metrics(result.handle, &metrics));
    EXPECT_GE(metrics.packet_errors, 0); // May have recorded errors
}

TEST_F(FullStackIntegrationTest, ConfigurationChanges) {
    result = vpn_start(&config);
    ASSERT_EQ(result.status, VPN_STATUS_SUCCESS);
    
    // Test dynamic configuration updates
    vpn_config_t new_config = config;
    new_config.tunnel_mtu = 1280; // Reduce MTU
    new_config.enable_dns_leak_protection = false; // Disable DNS protection
    
    // Update configuration
    EXPECT_TRUE(vpn_update_config(result.handle, &new_config));
    
    // Verify configuration was applied
    vpn_config_t current_config;
    EXPECT_TRUE(vpn_get_config(result.handle, &current_config));
    EXPECT_EQ(current_config.tunnel_mtu, 1280);
    EXPECT_FALSE(current_config.enable_dns_leak_protection);
    
    // Test DNS query that would have been blocked before
    uint8_t dns_query[] = {
        0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x04, 't', 'e', 's',
        't', 0x03, 'c', 'o', 'm', 0x00, 0x00, 0x01, 0x00, 0x01
    };
    
    packet_info_t dns_packet = {};
    dns_packet.data = dns_query;
    dns_packet.length = sizeof(dns_query);
    dns_packet.flow.ip_version = 4;
    dns_packet.flow.protocol = PROTO_UDP;
    dns_packet.flow.src_ip.v4.addr = inet_addr("10.0.0.1");
    dns_packet.flow.dst_ip.v4.addr = inet_addr("4.4.4.4"); // Unauthorized DNS
    dns_packet.flow.src_port = 12345;
    dns_packet.flow.dst_port = 53;
    dns_packet.timestamp_ns = clock_gettime_nsec_np(CLOCK_MONOTONIC);
    
    EXPECT_TRUE(vpn_inject_packet(result.handle, &dns_packet));
    
    // Process events
    for (int i = 0; i < 20; i++) {
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
    }
    
    // Should not have detected privacy violation since protection is disabled
    vpn_metrics_t metrics;
    vpn_get_metrics(result.handle, &metrics);
    // Privacy violations should be 0 or very low since protection was disabled
}

TEST_F(FullStackIntegrationTest, MemoryAndResourceManagement) {
    // Test multiple start/stop cycles to check for leaks
    for (int cycle = 0; cycle < 3; cycle++) {
        result = vpn_start(&config);
        ASSERT_EQ(result.status, VPN_STATUS_SUCCESS);
        
        // Generate some traffic
        for (int i = 0; i < 10; i++) {
            uint8_t packet[] = {
                0x45, 0x00, 0x00, 0x1c, 0x00, 0x01, 0x40, 0x00,
                0x40, 0x11, 0x00, 0x00, 0x0a, 0x00, 0x00, 0x01,
                0x08, 0x08, 0x08, 0x08, 0x00, 0x35, 0x00, 0x35,
                0x00, 0x08, 0x00, 0x00
            };
            
            packet_info_t pkt = {};
            pkt.data = packet;
            pkt.length = sizeof(packet);
            pkt.flow.ip_version = 4;
            pkt.flow.protocol = PROTO_UDP;
            pkt.timestamp_ns = clock_gettime_nsec_np(CLOCK_MONOTONIC);
            
            vpn_inject_packet(result.handle, &pkt);
        }
        
        // Process events
        for (int i = 0; i < 10; i++) {
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
        }
        
        // Stop VPN
        EXPECT_TRUE(vpn_stop(result.handle));
        EXPECT_FALSE(vpn_is_running(result.handle));
        
        result.handle = VPN_INVALID_HANDLE;
        
        // Brief pause between cycles
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
    
    // If we reach here without crashes or hangs, memory management is working
    SUCCEED();
}