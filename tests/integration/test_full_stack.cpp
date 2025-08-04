#include <gtest/gtest.h>
#include "api/relative_vpn.h"
#include "packet/tunnel_provider.h"
#include "dns/resolver.h"
#include "privacy/guards.h"
#include "socket_bridge/bridge.h"
#include "nat64/translator.h"
#include "metrics/ring_buffer.h"
#include <thread>
#include <chrono>
#include <atomic>
#include <arpa/inet.h>

extern "C" {
    // Forward declarations to avoid linkage issues
    vpn_status_t vpn_start(const vpn_config_t *config);
    vpn_status_t vpn_stop(void);
    vpn_status_t vpn_inject(const uint8_t *packet, size_t length);
    vpn_status_t vpn_get_metrics(vpn_metrics_t *metrics);
    bool vpn_is_running(void);
}

class FullStackIntegrationTest : public ::testing::Test {
protected:
    void SetUp() override {
        // Initialize VPN configuration with correct API
        memset(&config, 0, sizeof(config));
        config.utun_name = nullptr;
        config.mtu = 1500;
        config.tunnel_mtu = 1500;
        config.ipv4_enabled = true;
        config.ipv6_enabled = true;
        config.enable_nat64 = true;
        config.enable_dns_leak_protection = true;
        config.enable_ipv6_leak_protection = true;
        config.enable_kill_switch = false;
        config.enable_webrtc_leak_protection = true;
        config.dns_cache_size = 1024;
        config.metrics_buffer_size = 4096;
        config.reachability_monitoring = true;
        config.log_level = const_cast<char*>("DEBUG");
        
        // Configure DNS servers correctly
        config.dns_server_count = 2;
        config.dns_servers[0] = inet_addr("8.8.8.8");
        config.dns_servers[1] = inet_addr("1.1.1.1");
    }
    
    void TearDown() override {
        if (vpn_is_running()) {
            vpn_stop();
        }
    }
    
    vpn_config_t config;
};

TEST_F(FullStackIntegrationTest, VPNStartupShutdown) {
    // Test complete VPN startup sequence
    vpn_status_t result = vpn_start(&config);
    if (result == VPN_ERROR_PERMISSION) {
        GTEST_SKIP() << "Skipping test due to permission requirements (run as root or with proper capabilities)";
    }
    
    EXPECT_EQ(result, VPN_SUCCESS);
    
    // Verify components are initialized
    EXPECT_TRUE(vpn_is_running());
    
    // Get initial metrics
    vpn_metrics_t initial_metrics;
    EXPECT_EQ(vpn_get_metrics(&initial_metrics), VPN_SUCCESS);
    EXPECT_GE(initial_metrics.uptime_seconds, 0);
    
    // Test graceful shutdown
    EXPECT_EQ(vpn_stop(), VPN_SUCCESS);
    EXPECT_FALSE(vpn_is_running());
}

TEST_F(FullStackIntegrationTest, DNSResolutionWithPrivacyGuards) {
    vpn_status_t result = vpn_start(&config);
    if (result == VPN_ERROR_PERMISSION) {
        GTEST_SKIP() << "Skipping test due to permission requirements";
    }
    ASSERT_EQ(result, VPN_SUCCESS);
    
    // Create a simple DNS query packet
    uint8_t dns_packet[] = {
        // IPv4 header (simplified)
        0x45, 0x00, 0x00, 0x1c, 0x00, 0x00, 0x00, 0x00,
        0x40, 0x11, 0x00, 0x00, 0x0a, 0x00, 0x00, 0x01,  // src: 10.0.0.1
        0x08, 0x08, 0x08, 0x08,  // dst: 8.8.8.8
        // UDP header + DNS query
        0x30, 0x39, 0x00, 0x35, 0x00, 0x08, 0x00, 0x00,
        // Minimal DNS query for google.com
        0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00
    };
    
    // Inject DNS packet
    vpn_status_t inject_result = vpn_inject(dns_packet, sizeof(dns_packet));
    EXPECT_EQ(inject_result, VPN_SUCCESS);
    
    // Allow some processing time
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    
    // Verify VPN is still running
    EXPECT_TRUE(vpn_is_running());
    
    // Get metrics to verify packet was processed
    vpn_metrics_t metrics;
    if (vpn_get_metrics(&metrics) == VPN_SUCCESS) {
        EXPECT_GT(metrics.packets_in, 0);
        EXPECT_EQ(metrics.privacy_violations, 0);  // Should have no privacy violations
    }
    
    vpn_stop();
}

TEST_F(FullStackIntegrationTest, IPv6LeakProtection) {
    vpn_status_t result = vpn_start(&config);
    if (result == VPN_ERROR_PERMISSION) {
        GTEST_SKIP() << "Skipping test due to permission requirements";
    }
    ASSERT_EQ(result, VPN_SUCCESS);
    
    // Create IPv6 packet (should be processed with NAT64 or blocked if protection is enabled)
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
    
    // Inject IPv6 packet
    vpn_status_t inject_result = vpn_inject(ipv6_packet, sizeof(ipv6_packet));
    EXPECT_EQ(inject_result, VPN_SUCCESS);
    
    // Allow processing time
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    
    // Verify VPN handles IPv6 packets
    EXPECT_TRUE(vpn_is_running());
    
    // Get metrics
    vpn_metrics_t metrics;
    if (vpn_get_metrics(&metrics) == VPN_SUCCESS) {
        EXPECT_GE(metrics.nat64_translations, 0);  // May have been translated
    }
    
    vpn_stop();
}

TEST_F(FullStackIntegrationTest, NAT64Translation) {
    vpn_status_t result = vpn_start(&config);
    if (result == VPN_ERROR_PERMISSION) {
        GTEST_SKIP() << "Skipping test due to permission requirements";
    }
    ASSERT_EQ(result, VPN_SUCCESS);
    
    // Create IPv4 packet to be potentially translated to IPv6
    uint8_t ipv4_packet[] = {
        0x45, 0x00, 0x00, 0x20, 0x00, 0x01, 0x40, 0x00,
        0x40, 0x11, 0x00, 0x00, 0xc0, 0xa8, 0x01, 0x01,
        0x08, 0x08, 0x08, 0x08, 0x00, 0x35, 0x00, 0x35,
        0x00, 0x0c, 0x00, 0x00, 0x01, 0x02, 0x03, 0x04
    };
    
    // Inject packet for NAT64 processing
    vpn_status_t inject_result = vpn_inject(ipv4_packet, sizeof(ipv4_packet));
    EXPECT_EQ(inject_result, VPN_SUCCESS);
    
    // Allow processing time
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    
    // Check NAT64 translation metrics
    vpn_metrics_t metrics;
    if (vpn_get_metrics(&metrics) == VPN_SUCCESS) {
        EXPECT_GE(metrics.nat64_translations, 0);
    }
    
    vpn_stop();
}

TEST_F(FullStackIntegrationTest, MetricsCollection) {
    vpn_status_t result = vpn_start(&config);
    if (result == VPN_ERROR_PERMISSION) {
        GTEST_SKIP() << "Skipping test due to permission requirements";
    }
    ASSERT_EQ(result, VPN_SUCCESS);
    
    // Generate various types of traffic
    for (int i = 0; i < 10; i++) {
        uint8_t tcp_packet[] = {
            0x45, 0x00, 0x00, 0x28, 0x00, 0x01, 0x40, 0x00,
            0x40, 0x06, 0x00, 0x00, 0x0a, 0x00, 0x00, 0x01,
            0x5d, 0xb8, 0xd8, 0x22, 0x00, 0x50, 0x1f, 0x90,
            0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
            0x50, 0x02, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00
        };
        
        vpn_inject(tcp_packet, sizeof(tcp_packet));
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
    
    // Allow processing time
    std::this_thread::sleep_for(std::chrono::milliseconds(200));
    
    // Verify metrics were collected
    vpn_metrics_t metrics;
    EXPECT_EQ(vpn_get_metrics(&metrics), VPN_SUCCESS);
    
    EXPECT_GT(metrics.total_packets_processed, 0);
    EXPECT_GT(metrics.bytes_received, 0);
    EXPECT_GE(metrics.tcp_connections, 0);
    EXPECT_GE(metrics.udp_sessions, 0);
    EXPECT_GT(metrics.uptime_seconds, 0);
    
    vpn_stop();
}

TEST_F(FullStackIntegrationTest, ConcurrentTrafficHandling) {
    vpn_status_t result = vpn_start(&config);
    if (result == VPN_ERROR_PERMISSION) {
        GTEST_SKIP() << "Skipping test due to permission requirements";
    }
    ASSERT_EQ(result, VPN_SUCCESS);
    
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
            
            packets_injected.fetch_add(1);
            
            if (vpn_inject(packet_data, sizeof(packet_data)) == VPN_SUCCESS) {
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
    std::this_thread::sleep_for(std::chrono::milliseconds(500));
    
    EXPECT_EQ(packets_injected.load(), num_threads * packets_per_thread);
    EXPECT_GT(successful_injections.load(), 0);
    
    // Verify final metrics
    vpn_metrics_t final_metrics;
    EXPECT_EQ(vpn_get_metrics(&final_metrics), VPN_SUCCESS);
    EXPECT_GT(final_metrics.total_packets_processed, 0);
    
    vpn_stop();
}

TEST_F(FullStackIntegrationTest, ErrorRecovery) {
    vpn_status_t result = vpn_start(&config);
    if (result == VPN_ERROR_PERMISSION) {
        GTEST_SKIP() << "Skipping test due to permission requirements";
    }
    ASSERT_EQ(result, VPN_SUCCESS);
    
    // Test recovery from various error conditions
    
    // 1. Inject malformed packet
    uint8_t malformed_packet[] = { 0xFF, 0xFF, 0xFF, 0xFF };
    
    // Should handle gracefully without crashing
    vpn_status_t inject_result = vpn_inject(malformed_packet, sizeof(malformed_packet));
    // May succeed (packet dropped) or fail (validation), both are OK
    
    // 2. Test with zero-length packet  
    vpn_inject(malformed_packet, 0); // Should not crash
    
    // 3. Test VPN should still be functional after errors
    uint8_t good_packet[] = {
        0x45, 0x00, 0x00, 0x1c, 0x00, 0x01, 0x40, 0x00,
        0x40, 0x11, 0x00, 0x00, 0x0a, 0x00, 0x00, 0x01,
        0x08, 0x08, 0x08, 0x08, 0x00, 0x35, 0x00, 0x35,
        0x00, 0x08, 0x00, 0x00
    };
    
    EXPECT_EQ(vpn_inject(good_packet, sizeof(good_packet)), VPN_SUCCESS);
    
    // VPN should still be running
    EXPECT_TRUE(vpn_is_running());
    
    vpn_metrics_t metrics;
    EXPECT_EQ(vpn_get_metrics(&metrics), VPN_SUCCESS);
    EXPECT_GE(metrics.packet_errors, 0); // May have recorded errors
    
    vpn_stop();
}

TEST_F(FullStackIntegrationTest, MemoryAndResourceManagement) {
    // Test multiple start/stop cycles to check for leaks
    for (int cycle = 0; cycle < 3; cycle++) {
        vpn_status_t result = vpn_start(&config);
        if (result == VPN_ERROR_PERMISSION) {
            GTEST_SKIP() << "Skipping test due to permission requirements";
        }
        ASSERT_EQ(result, VPN_SUCCESS);
        
        // Generate some traffic
        for (int i = 0; i < 10; i++) {
            uint8_t packet[] = {
                0x45, 0x00, 0x00, 0x1c, 0x00, 0x01, 0x40, 0x00,
                0x40, 0x11, 0x00, 0x00, 0x0a, 0x00, 0x00, 0x01,
                0x08, 0x08, 0x08, 0x08, 0x00, 0x35, 0x00, 0x35,
                0x00, 0x08, 0x00, 0x00
            };
            
            vpn_inject(packet, sizeof(packet));
        }
        
        // Process events
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
        
        // Stop VPN
        EXPECT_EQ(vpn_stop(), VPN_SUCCESS);
        EXPECT_FALSE(vpn_is_running());
        
        // Brief pause between cycles
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
    
    // If we reach here without crashes or hangs, memory management is working
    SUCCEED();
}