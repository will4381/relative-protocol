#include <gtest/gtest.h>
#include "mtu/discovery.h"
#include <thread>
#include <chrono>
#include <atomic>

class MTUDiscoveryTest : public ::testing::Test {
protected:
    void SetUp() override {
        discovery = mtu_discovery_create();
        ASSERT_NE(discovery, nullptr);
    }
    
    void TearDown() override {
        if (discovery) {
            mtu_discovery_destroy(discovery);
        }
    }
    
    mtu_discovery_t *discovery;
};

TEST_F(MTUDiscoveryTest, CreateDestroy) {
    EXPECT_NE(discovery, nullptr);
    
    // Test default MTU
    EXPECT_GT(mtu_discovery_get_current_mtu(discovery), 0);
    EXPECT_LE(mtu_discovery_get_current_mtu(discovery), 1500);
}

TEST_F(MTUDiscoveryTest, MTUProbing) {
    ip_addr_t target = { .v4 = { .addr = inet_addr("8.8.8.8") } };
    
    std::atomic<bool> callback_called{false};
    std::atomic<uint16_t> discovered_mtu{0};
    
    auto callback = [](const ip_addr_t *addr, uint16_t mtu, void *user_data) {
        auto *called = static_cast<std::atomic<bool>*>(user_data);
        called->store(true);
        
        EXPECT_NE(addr, nullptr);
        EXPECT_GT(mtu, 0);
        EXPECT_LE(mtu, 1500);
    };
    
    mtu_discovery_set_callback(discovery, callback, &callback_called);
    
    // Start MTU discovery for target
    EXPECT_TRUE(mtu_discovery_start_probe(discovery, &target));
    
    // Wait for discovery to complete or timeout
    for (int i = 0; i < 50 && !callback_called.load(); i++) {
        mtu_discovery_process_events(discovery);
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
    
    // Check if we have an MTU value for the target
    uint16_t target_mtu = mtu_discovery_get_path_mtu(discovery, &target);
    if (target_mtu > 0) {
        EXPECT_GE(target_mtu, 576);  // IPv4 minimum
        EXPECT_LE(target_mtu, 1500);
    }
}

TEST_F(MTUDiscoveryTest, ManualMTUSetting) {
    ip_addr_t target = { .v4 = { .addr = inet_addr("192.168.1.1") } };
    
    // Set manual MTU
    EXPECT_TRUE(mtu_discovery_set_path_mtu(discovery, &target, 1280));
    EXPECT_EQ(mtu_discovery_get_path_mtu(discovery, &target), 1280);
    
    // Test invalid MTU values
    EXPECT_FALSE(mtu_discovery_set_path_mtu(discovery, &target, 0));
    EXPECT_FALSE(mtu_discovery_set_path_mtu(discovery, &target, 65536));
    EXPECT_FALSE(mtu_discovery_set_path_mtu(discovery, &target, 500)); // Below minimum
}

TEST_F(MTUDiscoveryTest, MSSclamping) {
    // Test MSS calculation for different MTU values
    EXPECT_EQ(mtu_calculate_mss(1500, false), 1460); // IPv4: 1500 - 20 (IP) - 20 (TCP)
    EXPECT_EQ(mtu_calculate_mss(1500, true), 1440);  // IPv6: 1500 - 40 (IP) - 20 (TCP)
    EXPECT_EQ(mtu_calculate_mss(1280, true), 1220);  // IPv6 minimum
    
    // Test MSS clamping
    uint8_t tcp_packet[] = {
        0x45, 0x00, 0x00, 0x28,  // IPv4 header
        0x00, 0x01, 0x40, 0x00,
        0x40, 0x06, 0x00, 0x00,
        0x7f, 0x00, 0x00, 0x01,
        0x7f, 0x00, 0x00, 0x01,
        0x00, 0x50, 0x1f, 0x90,  // TCP header
        0x00, 0x00, 0x00, 0x01,
        0x00, 0x00, 0x00, 0x00,
        0x60, 0x02, 0x20, 0x00,  // SYN flag, Window
        0x00, 0x00, 0x00, 0x00,
        0x02, 0x04, 0x05, 0xb4   // MSS option: 1460
    };
    
    flow_tuple_t flow = {};
    flow.ip_version = 4;
    flow.protocol = PROTO_TCP;
    flow.src_ip.v4.addr = inet_addr("127.0.0.1");
    flow.dst_ip.v4.addr = inet_addr("127.0.0.1");
    flow.src_port = 80;
    flow.dst_port = 8080;
    
    bool modified = mtu_clamp_mss(discovery, tcp_packet, sizeof(tcp_packet), &flow, 1280);
    
    // MSS should be clamped if original was too large
    if (modified) {
        // Check that MSS option was updated
        uint16_t *mss_ptr = (uint16_t*)(tcp_packet + sizeof(tcp_packet) - 2);
        uint16_t clamped_mss = ntohs(*mss_ptr);
        EXPECT_LE(clamped_mss, 1240); // 1280 - 40 (IP+TCP headers)
    }
}

TEST_F(MTUDiscoveryTest, PathMTUUpdates) {
    ip_addr_t target1 = { .v4 = { .addr = inet_addr("192.168.1.1") } };
    ip_addr_t target2 = { .v4 = { .addr = inet_addr("10.0.0.1") } };
    
    // Set different MTUs for different targets
    EXPECT_TRUE(mtu_discovery_set_path_mtu(discovery, &target1, 1500));
    EXPECT_TRUE(mtu_discovery_set_path_mtu(discovery, &target2, 1280));
    
    EXPECT_EQ(mtu_discovery_get_path_mtu(discovery, &target1), 1500);
    EXPECT_EQ(mtu_discovery_get_path_mtu(discovery, &target2), 1280);
    
    // Test MTU expiration
    mtu_discovery_set_cache_timeout(discovery, 1); // 1 second
    std::this_thread::sleep_for(std::chrono::seconds(2));
    
    mtu_discovery_cleanup_expired_entries(discovery);
    
    // MTU entries should be expired
    EXPECT_EQ(mtu_discovery_get_path_mtu(discovery, &target1), 0);
    EXPECT_EQ(mtu_discovery_get_path_mtu(discovery, &target2), 0);
}

TEST_F(MTUDiscoveryTest, ICMPProcessing) {
    // Create ICMP "Fragmentation Needed" packet
    uint8_t icmp_packet[] = {
        0x45, 0x00, 0x00, 0x38,  // IPv4 header
        0x00, 0x00, 0x00, 0x00,
        0x40, 0x01, 0x00, 0x00,  // ICMP protocol
        0x08, 0x08, 0x08, 0x08,  // Source (Google DNS)
        0xc0, 0xa8, 0x01, 0x01,  // Dest (local)
        0x03, 0x04, 0x00, 0x00,  // ICMP: Dest Unreachable, Frag Needed
        0x05, 0x00, 0x00, 0x00,  // Next-hop MTU: 1280
        // Original packet headers would follow...
        0x45, 0x00, 0x00, 0x1c,
        0x00, 0x01, 0x40, 0x00,
        0x40, 0x11, 0x00, 0x00,
        0xc0, 0xa8, 0x01, 0x01,
        0x08, 0x08, 0x08, 0x08
    };
    
    packet_info_t packet = {};
    packet.data = icmp_packet;
    packet.length = sizeof(icmp_packet);
    packet.flow.ip_version = 4;
    packet.flow.protocol = PROTO_ICMP;
    packet.flow.src_ip.v4.addr = inet_addr("8.8.8.8");
    packet.flow.dst_ip.v4.addr = inet_addr("192.168.1.1");
    packet.timestamp_ns = clock_gettime_nsec_np(CLOCK_MONOTONIC);
    
    // Process the ICMP packet
    mtu_discovery_process_icmp(discovery, &packet);
    
    // Check if MTU was updated for the destination
    ip_addr_t target = { .v4 = { .addr = inet_addr("8.8.8.8") } };
    uint16_t discovered_mtu = mtu_discovery_get_path_mtu(discovery, &target);
    
    if (discovered_mtu > 0) {
        EXPECT_EQ(discovered_mtu, 1280);
    }
}

TEST_F(MTUDiscoveryTest, Statistics) {
    mtu_stats_t stats;
    mtu_discovery_get_stats(discovery, &stats);
    
    EXPECT_EQ(stats.active_probes, 0);
    EXPECT_EQ(stats.completed_probes, 0);
    EXPECT_EQ(stats.icmp_messages_processed, 0);
    EXPECT_EQ(stats.mtu_updates, 0);
    
    // Trigger some activity
    ip_addr_t target = { .v4 = { .addr = inet_addr("8.8.8.8") } };
    mtu_discovery_start_probe(discovery, &target);
    
    mtu_discovery_get_stats(discovery, &stats);
    EXPECT_GT(stats.active_probes, 0);
}

TEST_F(MTUDiscoveryTest, ConcurrentProbes) {
    const int num_targets = 10;
    std::vector<ip_addr_t> targets;
    std::atomic<int> callbacks_received{0};
    
    auto callback = [](const ip_addr_t *addr, uint16_t mtu, void *user_data) {
        auto *counter = static_cast<std::atomic<int>*>(user_data);
        counter->fetch_add(1);
    };
    
    mtu_discovery_set_callback(discovery, callback, &callbacks_received);
    
    // Create multiple targets
    for (int i = 0; i < num_targets; i++) {
        ip_addr_t target = { .v4 = { .addr = htonl(0x08080800 + i) } };
        targets.push_back(target);
    }
    
    // Start probes for all targets
    for (const auto& target : targets) {
        EXPECT_TRUE(mtu_discovery_start_probe(discovery, &target));
    }
    
    // Process events
    for (int i = 0; i < 100; i++) {
        mtu_discovery_process_events(discovery);
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
    
    mtu_stats_t stats;
    mtu_discovery_get_stats(discovery, &stats);
    EXPECT_LE(stats.active_probes, num_targets);
}

TEST_F(MTUDiscoveryTest, ErrorHandling) {
    // Test null parameters
    EXPECT_FALSE(mtu_discovery_start_probe(nullptr, nullptr));
    EXPECT_FALSE(mtu_discovery_set_path_mtu(nullptr, nullptr, 1500));
    EXPECT_EQ(mtu_discovery_get_path_mtu(nullptr, nullptr), 0);
    
    ip_addr_t target = { .v4 = { .addr = inet_addr("192.168.1.1") } };
    
    EXPECT_FALSE(mtu_discovery_start_probe(discovery, nullptr));
    EXPECT_FALSE(mtu_discovery_set_path_mtu(discovery, nullptr, 1500));
    EXPECT_EQ(mtu_discovery_get_path_mtu(discovery, nullptr), 0);
    
    // Test operations on null discovery
    mtu_discovery_process_events(nullptr); // Should not crash
    mtu_discovery_cleanup_expired_entries(nullptr); // Should not crash
    mtu_discovery_destroy(nullptr); // Should not crash
}

TEST_F(MTUDiscoveryTest, IPv6Support) {
    ip_addr_t ipv6_target = {};
    ipv6_target.version = 6;
    ipv6_target.v6.addr[0] = 0x20;
    ipv6_target.v6.addr[1] = 0x01;
    ipv6_target.v6.addr[15] = 0x01;
    
    // Test IPv6 MTU discovery
    EXPECT_TRUE(mtu_discovery_start_probe(discovery, &ipv6_target));
    EXPECT_TRUE(mtu_discovery_set_path_mtu(discovery, &ipv6_target, 1280));
    EXPECT_EQ(mtu_discovery_get_path_mtu(discovery, &ipv6_target), 1280);
    
    // Test IPv6 MSS calculation
    EXPECT_EQ(mtu_calculate_mss(1280, true), 1220); // IPv6 minimum
    EXPECT_EQ(mtu_calculate_mss(1500, true), 1440); // Standard Ethernet
}

TEST_F(MTUDiscoveryTest, PacketSizeValidation) {
    // Test maximum transmission unit validation
    EXPECT_TRUE(mtu_is_valid_size(576));   // IPv4 minimum
    EXPECT_TRUE(mtu_is_valid_size(1280));  // IPv6 minimum
    EXPECT_TRUE(mtu_is_valid_size(1500));  // Ethernet standard
    EXPECT_TRUE(mtu_is_valid_size(9000));  // Jumbo frames
    
    EXPECT_FALSE(mtu_is_valid_size(0));
    EXPECT_FALSE(mtu_is_valid_size(575));  // Below IPv4 minimum
    EXPECT_FALSE(mtu_is_valid_size(65536)); // Too large
}