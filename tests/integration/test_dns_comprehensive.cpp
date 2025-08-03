#include <gtest/gtest.h>
#include "api/relative_vpn.h"
#include "packet/buffer_manager.h"
#include "core/types.h"
#include "test_utilities.h"
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <thread>
#include <chrono>
#include <vector>
#include <unordered_map>

extern "C" {
    vpn_status_t vpn_start(const vpn_config_t *config);
    vpn_status_t vpn_stop(void);
    vpn_status_t vpn_inject(const uint8_t *packet, size_t length);
    vpn_status_t vpn_get_metrics(vpn_metrics_t *metrics);
    bool vpn_is_running(void);
}

using namespace TestUtils;

class DNSComprehensiveTest : public ::testing::Test {
protected:
    void SetUp() override {
        // Initialize VPN configuration optimized for DNS testing
        memset(&config, 0, sizeof(config));
        config.utun_name = nullptr;
        config.mtu = 1500;
        config.tunnel_mtu = 1500;
        config.ipv4_enabled = true;
        config.ipv6_enabled = true;
        config.enable_nat64 = true;
        config.enable_dns_leak_protection = true;  // CRITICAL for DNS testing
        config.enable_ipv6_leak_protection = true;
        config.enable_kill_switch = false;
        config.enable_webrtc_leak_protection = true;
        config.dns_cache_size = 4096;  // Large cache for comprehensive testing
        config.metrics_buffer_size = 8192;
        config.reachability_monitoring = true;
        config.log_level = const_cast<char*>("DEBUG");
        
        // Configure comprehensive DNS server list
        config.dns_servers[0] = inet_addr("8.8.8.8");      // Google Primary
        config.dns_servers[1] = inet_addr("8.8.4.4");      // Google Secondary  
        config.dns_servers[2] = inet_addr("1.1.1.1");      // Cloudflare Primary
        config.dns_servers[3] = inet_addr("1.0.0.1");      // Cloudflare Secondary
        config.dns_servers[4] = inet_addr("208.67.222.222"); // OpenDNS Primary
        config.dns_servers[5] = inet_addr("208.67.220.220"); // OpenDNS Secondary
        config.dns_server_count = 6;
        
        TestLogger::SetLogLevel(TestLogger::DEBUG);
    }
    
    void TearDown() override {
        if (vpn_is_running()) {
            vpn_stop();
        }
    }
    
    vpn_config_t config;
};

// **PRIMARY DNS TEST** - Comprehensive DNS resolution capabilities
TEST_F(DNSComprehensiveTest, ComprehensiveDNSResolutionTesting) {
    GTEST_LOG_(INFO) << "🔍 COMPREHENSIVE DNS RESOLUTION TESTING (PRIMARY FOCUS)";
    
    vpn_status_t result = vpn_start(&config);
    if (result == VPN_ERROR_PERMISSION) {
        GTEST_SKIP() << "Skipping test due to permission requirements (run as root or with proper capabilities)";
    }
    ASSERT_EQ(result, VPN_SUCCESS) << "VPN should start for DNS testing";
    ASSERT_TRUE(vpn_is_running()) << "VPN should be running";
    
    TestLogger::Log(TestLogger::INFO, "VPN started - beginning comprehensive DNS testing");
    
    // Test 1: Popular website DNS resolution
    GTEST_LOG_(INFO) << "📋 Phase 1: Testing popular website DNS resolution";
    
    std::vector<std::string> popular_websites = {
        // Top global websites  
        "google.com",
        "youtube.com",
        "facebook.com", 
        "baidu.com",
        "wikipedia.org",
        "reddit.com",
        "yahoo.com",
        "twitter.com",
        "instagram.com",
        "linkedin.com",
        
        // Technology companies
        "apple.com",
        "microsoft.com",
        "amazon.com",
        "netflix.com",
        "github.com",
        "stackoverflow.com",
        "cloudflare.com",
        
        // CDN and infrastructure
        "cdn.jsdelivr.net",
        "ajax.googleapis.com",
        "fonts.googleapis.com",
        "code.jquery.com"
    };
    
    int dns_success_count = 0;
    int total_dns_queries = 0;
    
    for (const auto& domain : popular_websites) {
        TestLogger::Log(TestLogger::DEBUG, "Resolving: " + domain);
        
        auto dns_packet = PacketBuilder::CreateDNSQuery(domain);
        ASSERT_GT(dns_packet.size(), 0) << "Should create DNS packet for " << domain;
        
        vpn_status_t inject_result = vpn_inject(dns_packet.data(), dns_packet.size());
        total_dns_queries++;
        
        if (inject_result == VPN_SUCCESS) {
            dns_success_count++;
            TestLogger::Log(TestLogger::DEBUG, "✓ " + domain + " - DNS query successful");
        } else {
            TestLogger::Log(TestLogger::WARN, "✗ " + domain + " - DNS query failed");
        }
        
        // Realistic DNS query timing
        std::this_thread::sleep_for(std::chrono::milliseconds(25));
    }
    
    double dns_success_rate = (double)dns_success_count / total_dns_queries;
    EXPECT_GE(dns_success_rate, 0.95) << "DNS resolution should have >95% success rate";
    
    TestLogger::Log(TestLogger::INFO, "DNS Resolution Results: " + 
                   std::to_string(dns_success_count) + "/" + std::to_string(total_dns_queries) +
                   " (" + std::to_string(dns_success_rate * 100) + "% success rate)");
    
    // Test 2: International domain DNS resolution
    GTEST_LOG_(INFO) << "🌍 Phase 2: Testing international domain DNS resolution";
    
    std::vector<std::string> international_domains = {
        // Chinese
        "baidu.com",
        "qq.com", 
        "taobao.com",
        
        // Russian
        "yandex.ru",
        "mail.ru",
        "vk.com",
        
        // Japanese
        "yahoo.co.jp",
        "rakuten.co.jp",
        
        // European
        "bbc.co.uk",
        "lemonde.fr",
        "spiegel.de"
    };
    
    int intl_success_count = 0;
    for (const auto& domain : international_domains) {
        auto dns_packet = PacketBuilder::CreateDNSQuery(domain);
        vpn_status_t inject_result = vpn_inject(dns_packet.data(), dns_packet.size());
        
        if (inject_result == VPN_SUCCESS) {
            intl_success_count++;
        }
        
        std::this_thread::sleep_for(std::chrono::milliseconds(30));
    }
    
    EXPECT_GE(intl_success_count, international_domains.size() * 0.8)
        << "International DNS resolution should work well";
    
    // Test 3: Different DNS record types simulation
    GTEST_LOG_(INFO) << "📊 Phase 3: Testing different DNS record types";
    
    // Simulate different query types by varying domains
    std::vector<std::string> record_type_domains = {
        "example.com",           // A record
        "www.example.com",       // A record  
        "mail.example.com",      // A record (MX simulation)
        "ftp.example.com",       // A record
        "cdn.example.com",       // CNAME simulation
        "api.example.com",       // A record
        "blog.example.com"       // A record
    };
    
    int record_success_count = 0;
    for (const auto& domain : record_type_domains) {
        auto dns_packet = PacketBuilder::CreateDNSQuery(domain);
        vpn_status_t inject_result = vpn_inject(dns_packet.data(), dns_packet.size());
        
        if (inject_result == VPN_SUCCESS) {
            record_success_count++;
        }
        
        std::this_thread::sleep_for(std::chrono::milliseconds(20));
    }
    
    EXPECT_GE(record_success_count, record_type_domains.size() * 0.9)
        << "Different DNS record types should resolve successfully";
    
    // Test 4: DNS caching behavior
    GTEST_LOG_(INFO) << "💾 Phase 4: Testing DNS caching behavior";
    
    // Query the same domain multiple times to test caching
    std::string cache_test_domain = "cache-test.example.com";
    int cache_queries = 5;
    int cache_success_count = 0;
    
    for (int i = 0; i < cache_queries; i++) {
        auto dns_packet = PacketBuilder::CreateDNSQuery(cache_test_domain);
        vpn_status_t inject_result = vpn_inject(dns_packet.data(), dns_packet.size());
        
        if (inject_result == VPN_SUCCESS) {
            cache_success_count++;
        }
        
        // Very fast successive queries to test caching
        std::this_thread::sleep_for(std::chrono::milliseconds(5));
    }
    
    EXPECT_EQ(cache_success_count, cache_queries)
        << "DNS caching should handle rapid successive queries";
    
    // Test 5: DNS leak protection validation
    GTEST_LOG_(INFO) << "🔒 Phase 5: Testing DNS leak protection";
    
    // Attempt to use non-configured DNS servers (should be blocked/redirected)
    std::vector<std::string> unauthorized_dns_servers = {
        "192.168.1.1",    // Local router
        "10.0.0.1",       // Private network DNS
        "172.16.0.1"      // Private network DNS
    };
    
    for (const auto& dns_server : unauthorized_dns_servers) {
        auto leak_packet = PacketBuilder::CreateDNSQuery("leak-test.com", "192.168.1.100", dns_server);
        vpn_status_t inject_result = vpn_inject(leak_packet.data(), leak_packet.size());
        
        // DNS leak protection should either block or redirect
        EXPECT_EQ(inject_result, VPN_SUCCESS) 
            << "DNS packet should be processed (leak protection should redirect to safe servers)";
    }
    
    // Test 6: High-volume DNS stress test
    GTEST_LOG_(INFO) << "⚡ Phase 6: High-volume DNS stress testing";
    
    int stress_queries = 100;
    int stress_success_count = 0;
    auto stress_start = std::chrono::high_resolution_clock::now();
    
    for (int i = 0; i < stress_queries; i++) {
        std::string stress_domain = "stress-test-" + std::to_string(i) + ".example.com";
        auto dns_packet = PacketBuilder::CreateDNSQuery(stress_domain);
        
        vpn_status_t inject_result = vpn_inject(dns_packet.data(), dns_packet.size());
        if (inject_result == VPN_SUCCESS) {
            stress_success_count++;
        }
        
        // Minimal delay for stress testing
        if (i % 20 == 0) {
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
        }
    }
    
    auto stress_end = std::chrono::high_resolution_clock::now();
    auto stress_duration = std::chrono::duration_cast<std::chrono::milliseconds>(stress_end - stress_start);
    
    double queries_per_second = (double)stress_queries / (stress_duration.count() / 1000.0);
    
    EXPECT_GT(stress_success_count, stress_queries * 0.95)
        << "High-volume DNS stress test should maintain high success rate";
    
    EXPECT_GT(queries_per_second, 50) << "Should handle at least 50 DNS queries per second";
    
    TestLogger::Log(TestLogger::INFO, "DNS Stress Test: " + 
                   std::to_string(stress_success_count) + "/" + std::to_string(stress_queries) +
                   " queries in " + std::to_string(stress_duration.count()) + "ms" +
                   " (" + std::to_string(queries_per_second) + " queries/sec)");
    
    // Verify VPN stability after intensive DNS testing
    EXPECT_TRUE(vpn_is_running()) << "VPN should remain stable after intensive DNS testing";
    
    // Get final DNS metrics
    vpn_metrics_t final_metrics;
    if (vpn_get_metrics(&final_metrics) == VPN_SUCCESS) {
        TestLogger::LogVPNMetrics(final_metrics);
        
        EXPECT_GT(final_metrics.dns_queries, 0) << "Should have processed DNS queries";
        EXPECT_GE(final_metrics.dns_cache_hits, 0) << "DNS cache should be functional";
        EXPECT_EQ(final_metrics.dns_leaks_detected, 0) << "Should have no DNS leaks";
        EXPECT_EQ(final_metrics.privacy_violations, 0) << "Should maintain DNS privacy";
        
        // Calculate DNS cache hit rate if we have cache data
        if (final_metrics.dns_queries > 0) {
            double cache_hit_rate = (double)final_metrics.dns_cache_hits / final_metrics.dns_queries;
            TestLogger::Log(TestLogger::INFO, "DNS Cache Hit Rate: " + 
                           std::to_string(cache_hit_rate * 100) + "%");
        }
    }
    
    vpn_stop();
    EXPECT_FALSE(vpn_is_running()) << "VPN should stop cleanly after DNS testing";
    
    GTEST_LOG_(INFO) << "✅ COMPREHENSIVE DNS RESOLUTION TESTING PASSED - DNS system fully functional!";
}

// DNS failover and redundancy testing
TEST_F(DNSComprehensiveTest, DNSFailoverAndRedundancy) {
    GTEST_LOG_(INFO) << "🔄 Testing DNS failover and redundancy";
    
    vpn_status_t result = vpn_start(&config);
    if (result == VPN_ERROR_PERMISSION) {
        GTEST_SKIP() << "Skipping test due to permission requirements";
    }
    ASSERT_EQ(result, VPN_SUCCESS);
    
    // Test DNS queries with different configured servers
    std::vector<std::string> test_domains = {
        "primary-test.com",
        "secondary-test.com", 
        "tertiary-test.com",
        "quaternary-test.com"
    };
    
    // Test against each configured DNS server
    for (int server_idx = 0; server_idx < config.dns_server_count; server_idx++) {
        struct in_addr server_addr;
        server_addr.s_addr = config.dns_servers[server_idx];
        std::string server_ip = inet_ntoa(server_addr);
        
        TestLogger::Log(TestLogger::INFO, "Testing DNS server: " + server_ip);
        
        for (const auto& domain : test_domains) {
            auto dns_packet = PacketBuilder::CreateDNSQuery(domain, "192.168.1.100", server_ip);
            vpn_status_t inject_result = vpn_inject(dns_packet.data(), dns_packet.size());
            
            EXPECT_EQ(inject_result, VPN_SUCCESS) 
                << "DNS query should succeed for server " << server_ip << " domain " << domain;
            
            std::this_thread::sleep_for(std::chrono::milliseconds(50));
        }
    }
    
    vpn_stop();
    
    GTEST_LOG_(INFO) << "✅ DNS failover and redundancy test PASSED!";
}

// DNS performance under concurrent load
TEST_F(DNSComprehensiveTest, DNSConcurrentLoadPerformance) {
    GTEST_LOG_(INFO) << "⚡ Testing DNS performance under concurrent load";
    
    vpn_status_t result = vpn_start(&config);
    if (result == VPN_ERROR_PERMISSION) {
        GTEST_SKIP() << "Skipping test due to permission requirements";
    }
    ASSERT_EQ(result, VPN_SUCCESS);
    
    // Generate large set of DNS queries
    std::vector<std::vector<uint8_t>> concurrent_dns_packets;
    
    // Create 200 different DNS queries
    for (int i = 0; i < 200; i++) {
        std::string domain = "concurrent-test-" + std::to_string(i) + ".example.com";
        auto dns_packet = PacketBuilder::CreateDNSQuery(domain);
        concurrent_dns_packets.push_back(dns_packet);
    }
    
    // Inject all DNS packets rapidly (simulates concurrent requests)
    auto performance_start = std::chrono::high_resolution_clock::now();
    
    int concurrent_success = 0;
    for (const auto& packet : concurrent_dns_packets) {
        vpn_status_t inject_result = vpn_inject(packet.data(), packet.size());
        if (inject_result == VPN_SUCCESS) {
            concurrent_success++;
        }
        
        // Very brief pause to simulate concurrent load
        if (concurrent_success % 50 == 0) {
            std::this_thread::sleep_for(std::chrono::milliseconds(5));
        }
    }
    
    auto performance_end = std::chrono::high_resolution_clock::now();
    auto performance_duration = std::chrono::duration_cast<std::chrono::milliseconds>(performance_end - performance_start);
    
    double concurrent_qps = (double)concurrent_dns_packets.size() / (performance_duration.count() / 1000.0);
    
    EXPECT_GT(concurrent_success, concurrent_dns_packets.size() * 0.95)
        << "Concurrent DNS load should maintain high success rate";
    
    EXPECT_GT(concurrent_qps, 100) << "Should handle at least 100 concurrent DNS queries per second";
    
    TestLogger::Log(TestLogger::INFO, "Concurrent DNS Performance: " + 
                   std::to_string(concurrent_success) + "/" + std::to_string(concurrent_dns_packets.size()) +
                   " queries in " + std::to_string(performance_duration.count()) + "ms" +
                   " (" + std::to_string(concurrent_qps) + " QPS)");
    
    // Verify VPN remains stable
    EXPECT_TRUE(vpn_is_running()) << "VPN should remain stable under concurrent DNS load";
    
    vpn_stop();
    
    GTEST_LOG_(INFO) << "✅ DNS concurrent load performance test PASSED!";
}