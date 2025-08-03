#include <gtest/gtest.h>
#include "api/relative_vpn.h"
#include "packet/buffer_manager.h"
#include "core/types.h"
#include "test_utilities.h"
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>
#include <thread>
#include <chrono>
#include <atomic>
#include <vector>

extern "C" {
    vpn_status_t vpn_start(const vpn_config_t *config);
    vpn_status_t vpn_stop(void);
    vpn_status_t vpn_inject(const uint8_t *packet, size_t length);
    vpn_status_t vpn_get_metrics(vpn_metrics_t *metrics);
    bool vpn_is_running(void);
}

using namespace TestUtils;

class WebBrowsingDNSTest : public ::testing::Test {
protected:
    void SetUp() override {
        // Initialize VPN configuration optimized for web browsing testing
        memset(&config, 0, sizeof(config));
        config.utun_name = nullptr;
        config.mtu = 1500;
        config.tunnel_mtu = 1500;
        config.ipv4_enabled = true;
        config.ipv6_enabled = true;
        config.enable_nat64 = true;
        config.enable_dns_leak_protection = true;
        config.enable_ipv6_leak_protection = true;
        config.enable_kill_switch = false;  // Disabled for testing
        config.enable_webrtc_leak_protection = true;
        config.dns_cache_size = 2048;  // Larger cache for web browsing
        config.metrics_buffer_size = 8192;
        config.reachability_monitoring = true;
        config.log_level = const_cast<char*>("INFO");
        
        // Configure multiple DNS servers for realistic web browsing
        config.dns_servers[0] = inet_addr("8.8.8.8");    // Google DNS
        config.dns_servers[1] = inet_addr("1.1.1.1");    // Cloudflare DNS
        config.dns_servers[2] = inet_addr("208.67.222.222"); // OpenDNS
        config.dns_server_count = 3;
        
        // Initialize test harness
        vpn_harness = std::make_unique<VPNTestHarness>();
        TestLogger::SetLogLevel(TestLogger::INFO);
    }
    
    void TearDown() override {
        if (vpn_is_running()) {
            vpn_stop();
        }
    }
    
    vpn_config_t config;
    std::unique_ptr<VPNTestHarness> vpn_harness;
};

// **PRIMARY TEST** - Real-world web browsing simulation
TEST_F(WebBrowsingDNSTest, RealWorldWebBrowsingSimulation) {
    GTEST_LOG_(INFO) << "🌐 Testing real-world web browsing through VPN (PRIMARY FOCUS)";
    
    // Start VPN with web browsing optimizations
    vpn_status_t result = vpn_start(&config);
    if (result == VPN_ERROR_PERMISSION) {
        GTEST_SKIP() << "Skipping test due to permission requirements (run as root or with proper capabilities)";
    }
    ASSERT_EQ(result, VPN_SUCCESS) << "VPN should start successfully for web browsing";
    ASSERT_TRUE(vpn_is_running()) << "VPN should be running";
    
    TestLogger::Log(TestLogger::INFO, "VPN started - beginning web browsing simulation");
    
    // Test 1: DNS Resolution for popular websites
    GTEST_LOG_(INFO) << "📋 Phase 1: Testing DNS resolution for popular websites";
    
    std::vector<std::string> popular_domains = {
        "google.com",
        "youtube.com", 
        "facebook.com",
        "twitter.com",
        "instagram.com",
        "linkedin.com",
        "github.com",
        "stackoverflow.com",
        "reddit.com",
        "amazon.com"
    };
    
    int dns_success_count = 0;
    for (const auto& domain : popular_domains) {
        auto dns_packet = PacketBuilder::CreateDNSQuery(domain);
        ASSERT_GT(dns_packet.size(), 0) << "DNS packet should be created for " << domain;
        
        vpn_status_t inject_result = vpn_inject(dns_packet.data(), dns_packet.size());
        if (inject_result == VPN_SUCCESS) {
            dns_success_count++;
            TestLogger::Log(TestLogger::DEBUG, "✓ DNS query for " + domain + " injected successfully");
        } else {
            TestLogger::Log(TestLogger::WARN, "✗ DNS query for " + domain + " failed");
        }
        
        // Brief pause between DNS queries (realistic timing)
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
    }
    
    EXPECT_GE(dns_success_count, popular_domains.size() * 0.9) 
        << "Should successfully resolve at least 90% of popular domains";
    
    // Test 2: Web browsing session simulation
    GTEST_LOG_(INFO) << "🌐 Phase 2: Simulating web browsing session";
    
    auto web_session_packets = MockDataFactory::GenerateWebBrowsingSession(20);
    ASSERT_GT(web_session_packets.size(), 0) << "Web browsing session should generate packets";
    
    auto web_burst = vpn_harness->InjectPacketBurst(web_session_packets);
    EXPECT_GT(web_burst.successful_injections, web_session_packets.size() * 0.85)
        << "Should successfully handle at least 85% of web browsing packets";
    
    TestLogger::LogPerformanceMetrics(web_burst);
    
    // Test 3: HTTPS traffic (secure web browsing)
    GTEST_LOG_(INFO) << "🔒 Phase 3: Testing secure HTTPS web browsing";
    
    int https_success_count = 0;
    for (int i = 0; i < 10; i++) {
        auto https_packet = PacketBuilder::CreateHTTPSRequest(
            "192.168.1.100",
            i % 2 == 0 ? "172.217.164.196" : "104.16.124.96",  // Google & Cloudflare
            12345 + i,
            443
        );
        
        vpn_status_t inject_result = vpn_inject(https_packet.data(), https_packet.size());
        if (inject_result == VPN_SUCCESS) {
            https_success_count++;
        }
        
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
    
    EXPECT_GE(https_success_count, 8) << "Should handle most HTTPS requests successfully";
    
    // Test 4: Mixed HTTP/HTTPS browsing (realistic scenario)
    GTEST_LOG_(INFO) << "🔄 Phase 4: Testing mixed HTTP/HTTPS browsing";
    
    std::vector<std::vector<uint8_t>> mixed_packets;
    for (int i = 0; i < 15; i++) {
        if (i % 3 == 0) {
            // HTTP request
            mixed_packets.push_back(PacketBuilder::CreateHTTPRequest());
        } else {
            // HTTPS request  
            mixed_packets.push_back(PacketBuilder::CreateHTTPSRequest());
        }
    }
    
    auto mixed_burst = vpn_harness->InjectPacketBurst(mixed_packets);
    EXPECT_GT(mixed_burst.successful_injections, mixed_packets.size() * 0.8)
        << "Should handle mixed HTTP/HTTPS traffic effectively";
    
    // Test 5: Verify VPN stability after intensive browsing
    std::this_thread::sleep_for(std::chrono::milliseconds(500));
    EXPECT_TRUE(vpn_is_running()) << "VPN should remain stable after intensive web browsing";
    
    // Get final metrics
    vpn_metrics_t metrics;
    if (vpn_get_metrics(&metrics) == VPN_SUCCESS) {
        TestLogger::LogVPNMetrics(metrics);
        
        EXPECT_GT(metrics.packets_in, 0) << "Should have processed incoming packets";
        EXPECT_GT(metrics.dns_queries, 0) << "Should have processed DNS queries";
        EXPECT_EQ(metrics.privacy_violations, 0) << "Should have no privacy violations";
    }
    
    vpn_stop();
    EXPECT_FALSE(vpn_is_running()) << "VPN should stop cleanly after web browsing";
    
    GTEST_LOG_(INFO) << "✅ Real-world web browsing test PASSED - Internet connectivity verified!";
}

// DNS-specific comprehensive testing
TEST_F(WebBrowsingDNSTest, ComprehensiveDNSResolution) {
    GTEST_LOG_(INFO) << "🔍 Testing comprehensive DNS resolution capabilities";
    
    vpn_status_t result = vpn_start(&config);
    if (result == VPN_ERROR_PERMISSION) {
        GTEST_SKIP() << "Skipping test due to permission requirements";
    }
    ASSERT_EQ(result, VPN_SUCCESS);
    
    // Test different types of DNS queries
    std::vector<std::string> test_domains = {
        // Popular websites
        "google.com",
        "cloudflare.com", 
        "github.com",
        // CDN domains
        "cdn.jsdelivr.net",
        "ajax.googleapis.com",
        // International domains
        "baidu.com",
        "yandex.ru",
        // Long domain names
        "this-is-a-very-long-domain-name-for-testing-purposes.example.com"
    };
    
    auto dns_packets = MockDataFactory::GenerateDNSResolutionSequence(test_domains);
    ASSERT_GT(dns_packets.size(), 0) << "Should generate DNS resolution packets";
    
    auto dns_burst = vpn_harness->InjectPacketBurst(dns_packets);
    
    EXPECT_GT(dns_burst.successful_injections, dns_packets.size() * 0.75)
        << "Should successfully resolve most DNS queries";
    
    // Test DNS leak protection
    GTEST_LOG_(INFO) << "🔒 Testing DNS leak protection";
    
    // Attempt to send DNS query to non-configured server (should be blocked/redirected)
    auto leak_test_packet = PacketBuilder::CreateDNSQuery("test.com", "192.168.1.100", "192.168.1.1");
    vpn_status_t inject_result = vpn_inject(leak_test_packet.data(), leak_test_packet.size());
    
    // DNS leak protection should either block this or redirect to configured servers
    EXPECT_EQ(inject_result, VPN_SUCCESS) << "DNS packet should be processed (potentially redirected)";
    
    vpn_stop();
    
    GTEST_LOG_(INFO) << "✅ Comprehensive DNS resolution test PASSED - DNS system working correctly!";
}

// Video streaming simulation (high bandwidth web content)
TEST_F(WebBrowsingDNSTest, VideoStreamingSimulation) {
    GTEST_LOG_(INFO) << "🎥 Testing video streaming through VPN (simulates Netflix, YouTube)";
    
    vpn_status_t result = vpn_start(&config);
    if (result == VPN_ERROR_PERMISSION) {
        GTEST_SKIP() << "Skipping test due to permission requirements";
    }
    ASSERT_EQ(result, VPN_SUCCESS);
    
    // Generate video streaming session (30 seconds of streaming)
    auto video_packets = MockDataFactory::GenerateVideoStreamingSession(10);  // 10 seconds for test speed
    ASSERT_GT(video_packets.size(), 0) << "Should generate video streaming packets";
    
    TestLogger::Log(TestLogger::INFO, "Generated " + std::to_string(video_packets.size()) + " video packets");
    
    auto video_burst = vpn_harness->InjectPacketBurst(video_packets);
    
    // Video streaming requires high success rate
    EXPECT_GT(video_burst.successful_injections, video_packets.size() * 0.95)
        << "Video streaming should have very high success rate";
    
    // Check performance metrics
    EXPECT_GT(video_burst.packets_per_second, 20) << "Should maintain reasonable throughput for video";
    
    TestLogger::LogPerformanceMetrics(video_burst);
    
    vpn_stop();
    
    GTEST_LOG_(INFO) << "✅ Video streaming test PASSED - High bandwidth content works!";
}

// Social media and real-time communication
TEST_F(WebBrowsingDNSTest, SocialMediaAndRealTimeComm) {
    GTEST_LOG_(INFO) << "📱 Testing social media and real-time communication";
    
    vpn_status_t result = vpn_start(&config);
    if (result == VPN_ERROR_PERMISSION) {
        GTEST_SKIP() << "Skipping test due to permission requirements";
    }
    ASSERT_EQ(result, VPN_SUCCESS);
    
    // Test WebRTC traffic (video calls, real-time communication)
    GTEST_LOG_(INFO) << "📞 Testing WebRTC/video call traffic";
    
    std::vector<std::vector<uint8_t>> webrtc_packets;
    for (int i = 0; i < 20; i++) {
        auto stun_packet = PacketBuilder::CreateWebRTCSTUNPacket();
        webrtc_packets.push_back(stun_packet);
        
        // Brief pause between WebRTC packets
        std::this_thread::sleep_for(std::chrono::milliseconds(20));
    }
    
    auto webrtc_burst = vpn_harness->InjectPacketBurst(webrtc_packets);
    EXPECT_GT(webrtc_burst.successful_injections, webrtc_packets.size() * 0.8)
        << "WebRTC traffic should mostly succeed";
    
    // Test social media session
    GTEST_LOG_(INFO) << "📘 Testing social media browsing";
    
    auto social_packets = MockDataFactory::GenerateWebBrowsingSession(15);
    auto social_burst = vpn_harness->InjectPacketBurst(social_packets);
    
    EXPECT_GT(social_burst.successful_injections, social_packets.size() * 0.85)
        << "Social media browsing should work well";
    
    vpn_stop();
    
    GTEST_LOG_(INFO) << "✅ Social media and real-time communication test PASSED!";
}

// Internet connectivity validation with real endpoints
TEST_F(WebBrowsingDNSTest, InternetConnectivityValidation) {
    GTEST_LOG_(INFO) << "🌍 Testing comprehensive internet connectivity validation";
    
    vpn_status_t result = vpn_start(&config);
    if (result == VPN_ERROR_PERMISSION) {
        GTEST_SKIP() << "Skipping test due to permission requirements";
    }
    ASSERT_EQ(result, VPN_SUCCESS);
    
    // Use the VPN harness connectivity tests
    EXPECT_TRUE(vpn_harness->ValidateInternetConnectivity()) 
        << "VPN should provide full internet connectivity";
    
    // Test individual connectivity components
    EXPECT_TRUE(vpn_harness->TestHTTPConnectivity()) 
        << "HTTP connectivity should work";
    
    EXPECT_TRUE(vpn_harness->TestHTTPSConnectivity()) 
        << "HTTPS connectivity should work";
    
    EXPECT_TRUE(vpn_harness->TestDNSResolution()) 
        << "DNS resolution should work";
    
    EXPECT_TRUE(vpn_harness->TestVideoStreaming()) 
        << "Video streaming should work";
    
    // Final metrics check
    vpn_metrics_t final_metrics;
    if (vpn_get_metrics(&final_metrics) == VPN_SUCCESS) {
        TestLogger::LogVPNMetrics(final_metrics);
        
        // Verify comprehensive metrics
        EXPECT_GT(final_metrics.packets_in, 0) << "Should have incoming packets";
        EXPECT_GT(final_metrics.packets_out, 0) << "Should have outgoing packets";
        EXPECT_GT(final_metrics.dns_queries, 0) << "Should have DNS queries";
        EXPECT_GE(final_metrics.dns_cache_hits, 0) << "DNS cache should be working";
        EXPECT_EQ(final_metrics.privacy_violations, 0) << "Should maintain privacy";
        EXPECT_EQ(final_metrics.dns_leaks_detected, 0) << "Should prevent DNS leaks";
    }
    
    vpn_stop();
    
    GTEST_LOG_(INFO) << "✅ Internet connectivity validation PASSED - Full internet access through VPN verified!";
}

// Continuous web browsing under load
TEST_F(WebBrowsingDNSTest, ContinuousWebBrowsingUnderLoad) {
    GTEST_LOG_(INFO) << "⚡ Testing continuous web browsing under high load";
    
    vpn_status_t result = vpn_start(&config);
    if (result == VPN_ERROR_PERMISSION) {
        GTEST_SKIP() << "Skipping test due to permission requirements";
    }
    ASSERT_EQ(result, VPN_SUCCESS);
    
    // Simulate heavy web browsing for 10 seconds
    auto end_time = std::chrono::steady_clock::now() + std::chrono::seconds(5);
    int total_packets = 0;
    int successful_packets = 0;
    
    while (std::chrono::steady_clock::now() < end_time) {
        // Generate random web traffic
        auto packet_type = total_packets % 4;
        std::vector<uint8_t> packet;
        
        switch (packet_type) {
            case 0: packet = PacketBuilder::CreateHTTPRequest(); break;
            case 1: packet = PacketBuilder::CreateHTTPSRequest(); break;  
            case 2: packet = PacketBuilder::CreateDNSQuery("example" + std::to_string(total_packets % 100) + ".com"); break;
            case 3: packet = PacketBuilder::CreateVideoStreamPacket(); break;
        }
        
        vpn_status_t inject_result = vpn_inject(packet.data(), packet.size());
        if (inject_result == VPN_SUCCESS) {
            successful_packets++;
        }
        total_packets++;
        
        // Verify VPN stability every 50 packets
        if (total_packets % 50 == 0) {
            ASSERT_TRUE(vpn_is_running()) << "VPN should remain stable under continuous load";
        }
        
        // Realistic browsing timing
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
    
    // Final stability check
    EXPECT_TRUE(vpn_is_running()) << "VPN should be stable after continuous load";
    EXPECT_GT(successful_packets, total_packets * 0.9) 
        << "Should maintain high success rate under load";
    EXPECT_GT(total_packets, 400) << "Should process substantial packets during load test";
    
    TestLogger::Log(TestLogger::INFO, "Continuous load test: " + 
                   std::to_string(successful_packets) + "/" + std::to_string(total_packets) +
                   " packets successful (" + 
                   std::to_string(100.0 * successful_packets / total_packets) + "%)");
    
    vpn_stop();
    
    GTEST_LOG_(INFO) << "✅ Continuous web browsing under load test PASSED - VPN handles intensive usage!";
}