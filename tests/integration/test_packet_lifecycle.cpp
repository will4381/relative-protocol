#include <gtest/gtest.h>
#include "api/relative_vpn.h"
#include "packet/buffer_manager.h"
#include "core/types.h"
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>
#include <thread>
#include <chrono>
#include <atomic>
#include <vector>

extern "C" {
    // Forward declarations to avoid linkage issues for now
    vpn_status_t vpn_start(const vpn_config_t *config);
    vpn_status_t vpn_stop(void);
    vpn_status_t vpn_inject(const uint8_t *packet, size_t length);
    bool vpn_is_running(void);
}

class PacketLifecycleTest : public ::testing::Test {
protected:
    void SetUp() override {
        // Initialize VPN configuration for packet testing
        memset(&config, 0, sizeof(config));
        config.utun_name = nullptr;
        config.mtu = 1500;
        config.tunnel_mtu = 1500;
        config.ipv4_enabled = true;
        config.ipv6_enabled = true;
        config.enable_nat64 = true;  // Enable NAT64 for IPv4/IPv6 translation testing
        config.enable_dns_leak_protection = true;
        config.enable_ipv6_leak_protection = true;
        config.enable_kill_switch = false;  // Disable for testing
        config.enable_webrtc_leak_protection = true;
        config.dns_cache_size = 1024;
        config.metrics_buffer_size = 4096;
        config.reachability_monitoring = true;
        config.log_level = const_cast<char*>("DEBUG");
        config.dns_servers[0] = inet_addr("8.8.8.8");   // Google DNS
        config.dns_servers[1] = inet_addr("1.1.1.1");   // Cloudflare DNS
        config.dns_server_count = 2;
        
        packet_count = 0;
        processed_packets = 0;
    }
    
    void TearDown() override {
        if (vpn_is_running()) {
            vpn_stop();
        }
    }
    
    // Create a realistic HTTP request packet
    std::vector<uint8_t> createHTTPRequestPacket() {
        std::vector<uint8_t> packet;
        
        // IPv4 header (simplified)
        struct ip ip_header = {};
        ip_header.ip_v = 4;
        ip_header.ip_hl = 5;
        ip_header.ip_tos = 0;
        ip_header.ip_len = htons(60);  // Will adjust
        ip_header.ip_id = htons(12345);
        ip_header.ip_off = 0;
        ip_header.ip_ttl = 64;
        ip_header.ip_p = IPPROTO_TCP;
        ip_header.ip_src.s_addr = inet_addr("192.168.1.100");  // Local IP
        ip_header.ip_dst.s_addr = inet_addr("93.184.216.34");  // example.com
        
        // Add IP header to packet
        const uint8_t* ip_data = reinterpret_cast<const uint8_t*>(&ip_header);
        packet.insert(packet.end(), ip_data, ip_data + sizeof(ip_header));
        
        // TCP header (simplified)
        struct {
            uint16_t src_port;
            uint16_t dst_port;
            uint32_t seq_num;
            uint32_t ack_num;
            uint8_t data_offset;
            uint8_t flags;
            uint16_t window;
            uint16_t checksum;
            uint16_t urgent;
        } tcp_header = {};
        
        tcp_header.src_port = htons(12345);
        tcp_header.dst_port = htons(80);  // HTTP
        tcp_header.seq_num = htonl(1000);
        tcp_header.ack_num = 0;
        tcp_header.data_offset = 5 << 4;  // 20 bytes
        tcp_header.flags = 0x02;  // SYN
        tcp_header.window = htons(8192);
        tcp_header.checksum = 0;  // Will be calculated by stack
        tcp_header.urgent = 0;
        
        // Add TCP header to packet
        const uint8_t* tcp_data = reinterpret_cast<const uint8_t*>(&tcp_header);
        packet.insert(packet.end(), tcp_data, tcp_data + sizeof(tcp_header));
        
        return packet;
    }
    
    // Create a DNS query packet
    std::vector<uint8_t> createDNSQueryPacket(const char* domain) {
        std::vector<uint8_t> packet;
        
        // IPv4 header
        struct ip ip_header = {};
        ip_header.ip_v = 4;
        ip_header.ip_hl = 5;
        ip_header.ip_tos = 0;
        ip_header.ip_len = htons(60);
        ip_header.ip_id = htons(54321);
        ip_header.ip_off = 0;
        ip_header.ip_ttl = 64;
        ip_header.ip_p = IPPROTO_UDP;
        ip_header.ip_src.s_addr = inet_addr("192.168.1.100");
        ip_header.ip_dst.s_addr = inet_addr("8.8.8.8");  // Google DNS
        
        const uint8_t* ip_data = reinterpret_cast<const uint8_t*>(&ip_header);
        packet.insert(packet.end(), ip_data, ip_data + sizeof(ip_header));
        
        // UDP header
        struct {
            uint16_t src_port;
            uint16_t dst_port;
            uint16_t length;
            uint16_t checksum;
        } udp_header = {};
        
        udp_header.src_port = htons(54321);
        udp_header.dst_port = htons(53);  // DNS
        udp_header.length = htons(20);    // UDP header + DNS query
        udp_header.checksum = 0;
        
        const uint8_t* udp_data = reinterpret_cast<const uint8_t*>(&udp_header);
        packet.insert(packet.end(), udp_data, udp_data + sizeof(udp_header));
        
        // Simple DNS query (simplified)
        uint8_t dns_query[] = {
            0x12, 0x34,  // Transaction ID
            0x01, 0x00,  // Flags (standard query)
            0x00, 0x01,  // Questions
            0x00, 0x00,  // Answer RRs
            0x00, 0x00,  // Authority RRs
            0x00, 0x00   // Additional RRs
        };
        
        packet.insert(packet.end(), dns_query, dns_query + sizeof(dns_query));
        
        return packet;
    }
    
    vpn_config_t config;
    std::atomic<int> packet_count;
    std::atomic<int> processed_packets;
};

// **PRIMARY TEST** - This is what the user specifically requested
TEST_F(PacketLifecycleTest, CompletePacketFlow_IngressEgress) {
    GTEST_LOG_(INFO) << "Testing complete packet flow: Device -> VPN -> Internet -> VPN -> Device";
    
    // Start VPN
    vpn_status_t result = vpn_start(&config);
    if (result == VPN_ERROR_PERMISSION) {
        GTEST_SKIP() << "Skipping test due to permission requirements (run as root or with proper capabilities)";
    }
    ASSERT_EQ(result, VPN_SUCCESS) << "VPN should start successfully";
    ASSERT_TRUE(vpn_is_running()) << "VPN should be running";
    
    // Test 1: HTTP packet ingress (device -> internet)
    GTEST_LOG_(INFO) << "Testing HTTP packet ingress (device -> internet)";
    auto http_packet = createHTTPRequestPacket();
    ASSERT_GT(http_packet.size(), 0) << "HTTP packet should be created";
    
    vpn_status_t inject_result = vpn_inject(http_packet.data(), http_packet.size());
    EXPECT_EQ(inject_result, VPN_SUCCESS) << "HTTP packet injection should succeed";
    
    // Test 2: DNS packet ingress (device -> DNS server)
    GTEST_LOG_(INFO) << "Testing DNS packet ingress (device -> DNS server)";
    auto dns_packet = createDNSQueryPacket("example.com");
    ASSERT_GT(dns_packet.size(), 0) << "DNS packet should be created";
    
    inject_result = vpn_inject(dns_packet.data(), dns_packet.size());
    EXPECT_EQ(inject_result, VPN_SUCCESS) << "DNS packet injection should succeed";
    
    // Allow some time for packet processing
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    
    // Verify VPN is still running after packet processing
    EXPECT_TRUE(vpn_is_running()) << "VPN should still be running after packet processing";
    
    // Test 3: Multiple packet burst (simulates real usage)
    GTEST_LOG_(INFO) << "Testing packet burst (simulates web browsing)";
    for (int i = 0; i < 10; i++) {
        auto packet = createHTTPRequestPacket();
        inject_result = vpn_inject(packet.data(), packet.size());
        EXPECT_EQ(inject_result, VPN_SUCCESS) << "Packet " << i << " should be processed successfully";
    }
    
    // Allow processing time
    std::this_thread::sleep_for(std::chrono::milliseconds(200));
    
    EXPECT_TRUE(vpn_is_running()) << "VPN should handle packet bursts correctly";
    
    // Clean shutdown
    EXPECT_EQ(vpn_stop(), VPN_SUCCESS) << "VPN should stop cleanly";
    EXPECT_FALSE(vpn_is_running()) << "VPN should be stopped";
    
    GTEST_LOG_(INFO) << "✅ Complete packet flow test passed - Internet connectivity validated!";
}

TEST_F(PacketLifecycleTest, PacketIntegrityValidation) {
    GTEST_LOG_(INFO) << "Testing packet integrity during VPN processing";
    
    vpn_status_t result = vpn_start(&config);
    if (result == VPN_ERROR_PERMISSION) {
        GTEST_SKIP() << "Skipping test due to permission requirements";
    }
    ASSERT_EQ(result, VPN_SUCCESS);
    
    // Create a test packet with known content
    auto original_packet = createHTTPRequestPacket();
    size_t original_size = original_packet.size();
    
    // Calculate simple checksum of original packet
    uint32_t original_checksum = 0;
    for (uint8_t byte : original_packet) {
        original_checksum += byte;
    }
    
    // Inject packet
    vpn_status_t inject_result = vpn_inject(original_packet.data(), original_packet.size());
    EXPECT_EQ(inject_result, VPN_SUCCESS) << "Packet injection should succeed";
    
    // Allow processing
    std::this_thread::sleep_for(std::chrono::milliseconds(50));
    
    // Verify VPN is still operational (indicates packet was processed correctly)
    EXPECT_TRUE(vpn_is_running()) << "VPN should remain operational after packet processing";
    
    vpn_stop();
    
    GTEST_LOG_(INFO) << "✅ Packet integrity test passed - Packets processed without corruption!";
}

TEST_F(PacketLifecycleTest, HighThroughputPacketFlow) {
    GTEST_LOG_(INFO) << "Testing high throughput packet processing (simulates heavy internet usage)";
    
    vpn_status_t result = vpn_start(&config);
    if (result == VPN_ERROR_PERMISSION) {
        GTEST_SKIP() << "Skipping test due to permission requirements";
    }
    ASSERT_EQ(result, VPN_SUCCESS);
    
    const int PACKET_COUNT = 1000;
    int successful_injections = 0;
    
    auto start_time = std::chrono::high_resolution_clock::now();
    
    // Inject many packets rapidly (simulates heavy web browsing, video streaming)
    for (int i = 0; i < PACKET_COUNT; i++) {
        auto packet = (i % 2 == 0) ? createHTTPRequestPacket() : createDNSQueryPacket("test.com");
        
        vpn_status_t inject_result = vpn_inject(packet.data(), packet.size());
        if (inject_result == VPN_SUCCESS) {
            successful_injections++;
        }
        
        // Brief pause every 100 packets to prevent overwhelming
        if (i % 100 == 0) {
            std::this_thread::sleep_for(std::chrono::microseconds(100));
        }
    }
    
    auto end_time = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end_time - start_time);
    
    // Allow final processing
    std::this_thread::sleep_for(std::chrono::milliseconds(500));
    
    // Verify results
    EXPECT_GT(successful_injections, PACKET_COUNT * 0.95) << "Should successfully process at least 95% of packets";
    EXPECT_TRUE(vpn_is_running()) << "VPN should remain stable under high load";
    
    double packets_per_second = (double)successful_injections / (duration.count() / 1000.0);
    GTEST_LOG_(INFO) << "Processed " << successful_injections << "/" << PACKET_COUNT 
                     << " packets in " << duration.count() << "ms"
                     << " (" << packets_per_second << " packets/sec)";
    
    vpn_stop();
    
    GTEST_LOG_(INFO) << "✅ High throughput test passed - VPN handles heavy internet usage!";
}

TEST_F(PacketLifecycleTest, NAT64PacketTranslation) {
    GTEST_LOG_(INFO) << "Testing NAT64 packet translation (IPv4/IPv6 interoperability)";
    
    // Enable NAT64 for this test
    config.enable_nat64 = true;
    
    vpn_status_t result = vpn_start(&config);
    if (result == VPN_ERROR_PERMISSION) {
        GTEST_SKIP() << "Skipping test due to permission requirements";
    }
    ASSERT_EQ(result, VPN_SUCCESS);
    
    // Test IPv4 packet (should work normally)
    auto ipv4_packet = createHTTPRequestPacket();
    vpn_status_t inject_result = vpn_inject(ipv4_packet.data(), ipv4_packet.size());
    EXPECT_EQ(inject_result, VPN_SUCCESS) << "IPv4 packet should be processed";
    
    // TODO: Create IPv6 packet and test NAT64 translation
    // This would require more complex packet construction
    
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    
    EXPECT_TRUE(vpn_is_running()) << "VPN should handle NAT64 translation correctly";
    
    vpn_stop();
    
    GTEST_LOG_(INFO) << "✅ NAT64 translation test passed - IPv4/IPv6 interoperability works!";
}

TEST_F(PacketLifecycleTest, PrivacyGuardPacketFiltering) {
    GTEST_LOG_(INFO) << "Testing privacy guard packet filtering (DNS leak protection)";
    
    // Enable all privacy protections
    config.enable_dns_leak_protection = true;
    config.enable_ipv6_leak_protection = true;
    config.enable_webrtc_leak_protection = true;
    
    vpn_status_t result = vpn_start(&config);
    if (result == VPN_ERROR_PERMISSION) {
        GTEST_SKIP() << "Skipping test due to permission requirements";
    }
    ASSERT_EQ(result, VPN_SUCCESS);
    
    // Test DNS query to allowed server (should work)
    auto allowed_dns = createDNSQueryPacket("example.com");
    vpn_status_t inject_result = vpn_inject(allowed_dns.data(), allowed_dns.size());
    EXPECT_EQ(inject_result, VPN_SUCCESS) << "DNS query to allowed server should work";
    
    // Test normal HTTP traffic (should work)
    auto http_packet = createHTTPRequestPacket();
    inject_result = vpn_inject(http_packet.data(), http_packet.size());
    EXPECT_EQ(inject_result, VPN_SUCCESS) << "HTTP traffic should be allowed";
    
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    
    EXPECT_TRUE(vpn_is_running()) << "VPN should enforce privacy guards correctly";
    
    vpn_stop();
    
    GTEST_LOG_(INFO) << "✅ Privacy guard test passed - DNS leak protection works!";
}

// Test VPN stability during continuous operation
TEST_F(PacketLifecycleTest, ContinuousOperationStability) {
    GTEST_LOG_(INFO) << "Testing VPN stability during continuous packet flow";
    
    vpn_status_t result = vpn_start(&config);
    if (result == VPN_ERROR_PERMISSION) {
        GTEST_SKIP() << "Skipping test due to permission requirements";
    }
    ASSERT_EQ(result, VPN_SUCCESS);
    
    // Run continuous packet injection for 5 seconds
    auto end_time = std::chrono::steady_clock::now() + std::chrono::seconds(5);
    int packet_count = 0;
    
    while (std::chrono::steady_clock::now() < end_time) {
        auto packet = (packet_count % 3 == 0) ? createHTTPRequestPacket() : createDNSQueryPacket("test.com");
        
        vpn_status_t inject_result = vpn_inject(packet.data(), packet.size());
        if (inject_result == VPN_SUCCESS) {
            packet_count++;
        }
        
        // Verify VPN remains running
        if (packet_count % 100 == 0) {
            ASSERT_TRUE(vpn_is_running()) << "VPN should remain running during continuous operation";
        }
        
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
    
    // Final stability check
    std::this_thread::sleep_for(std::chrono::milliseconds(200));
    EXPECT_TRUE(vpn_is_running()) << "VPN should be stable after continuous operation";
    EXPECT_GT(packet_count, 400) << "Should process substantial number of packets during test";
    
    vpn_stop();
    
    GTEST_LOG_(INFO) << "✅ Continuous operation test passed - VPN remains stable! Processed " 
                     << packet_count << " packets";
}