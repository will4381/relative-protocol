#include <gtest/gtest.h>
#include "api/relative_vpn.h"
#include "privacy/guards.h"
#include "core/types.h"
#include <arpa/inet.h>
#include <cstring>

class IPv6HandlingTest : public ::testing::Test {
protected:
    void SetUp() override {
        guards = privacy_guards_create();
        ASSERT_NE(guards, nullptr);
        
        // Enable IPv6 leak protection for testing
        ASSERT_TRUE(privacy_guards_enable_ipv6_leak_protection(guards, true));
        
        // Configure allowed DNS servers to prevent DNS leak false positives
        ip_addr_t dns_servers[3];
        // IPv4 DNS servers
        dns_servers[0].v4.addr = inet_addr("8.8.8.8");
        dns_servers[1].v4.addr = inet_addr("1.1.1.1");
        // IPv6 DNS server (Google)
        dns_servers[2].v4.addr = 0; // Mark as IPv6
        inet_pton(AF_INET6, "2001:4860:4860::8888", &dns_servers[2].v6.addr);
        
        ASSERT_TRUE(privacy_guards_set_allowed_dns_servers(guards, dns_servers, 3));
    }

    void TearDown() override {
        if (guards) {
            privacy_guards_destroy(guards);
        }
    }

    privacy_guards_t *guards = nullptr;

    // Helper function to create IPv6 flow tuple
    flow_tuple_t create_ipv6_flow(const char *dst_ipv6, uint16_t dst_port, uint8_t protocol) {
        flow_tuple_t flow = {};
        flow.ip_version = 6;
        flow.protocol = protocol;
        flow.dst_port = dst_port;
        flow.src_port = 12345;

        // CRITICAL: Initialize the ENTIRE dst_ip structure to zero first
        memset(&flow.dst_ip, 0, sizeof(flow.dst_ip));
        
        // Parse IPv6 address into the v6 field
        int result = inet_pton(AF_INET6, dst_ipv6, &flow.dst_ip.v6.addr);
        if (result != 1) {
            GTEST_LOG_(ERROR) << "Failed to parse IPv6 address: " << dst_ipv6;
        }

        // Debug: Print parsed IPv6 address
        GTEST_LOG_(INFO) << "Created IPv6 flow to " << dst_ipv6 << ":" << dst_port 
                         << " [" << std::hex << (int)flow.dst_ip.v6.addr[0] 
                         << ":" << (int)flow.dst_ip.v6.addr[1] << "..." << std::dec << "]"
                         << " v4.addr=" << flow.dst_ip.v4.addr;

        return flow;
    }

    // Helper function to create IPv4 flow tuple
    flow_tuple_t create_ipv4_flow(const char *dst_ipv4, uint16_t dst_port, uint8_t protocol) {
        flow_tuple_t flow = {};
        flow.ip_version = 4;
        flow.protocol = protocol;
        flow.dst_port = dst_port;
        flow.src_port = 12345;
        flow.dst_ip.v4.addr = inet_addr(dst_ipv4);

        return flow;
    }
};

TEST_F(IPv6HandlingTest, DualStackVPN_AllowsLegitimateIPv6Traffic) {
    GTEST_LOG_(INFO) << "Testing dual-stack VPN allows legitimate IPv6 traffic";

    // Configure VPN as dual-stack with active tunnel
    ASSERT_TRUE(privacy_guards_set_vpn_config(guards, true, true, true));

    // Test legitimate IPv6 traffic to Google DNS
    flow_tuple_t flow = create_ipv6_flow("2001:4860:4860::8888", 53, PROTO_UDP);
    
    uint8_t dummy_packet[64] = {0};
    bool should_block = false;

    ASSERT_TRUE(privacy_guards_inspect_packet(guards, dummy_packet, sizeof(dummy_packet), &flow, &should_block));
    EXPECT_FALSE(should_block) << "Dual-stack VPN should allow legitimate IPv6 traffic";

    // Verify no leak was detected
    privacy_stats_t stats;
    privacy_guards_get_stats(guards, &stats);
    EXPECT_EQ(stats.ipv6_leaks_detected, 0) << "No IPv6 leak should be detected in dual-stack VPN";
}

TEST_F(IPv6HandlingTest, IPv4OnlyVPN_BlocksIPv6Traffic) {
    GTEST_LOG_(INFO) << "Testing IPv4-only VPN blocks IPv6 traffic (except local)";

    // Configure VPN as IPv4-only with active tunnel
    ASSERT_TRUE(privacy_guards_set_vpn_config(guards, true, false, true));
    ASSERT_TRUE(privacy_guards_enable_kill_switch(guards, true));

    // Test IPv6 traffic to Google DNS - should be blocked
    flow_tuple_t flow = create_ipv6_flow("2001:4860:4860::8888", 53, PROTO_UDP);
    
    uint8_t dummy_packet[64] = {0};
    bool should_block = false;

    ASSERT_TRUE(privacy_guards_inspect_packet(guards, dummy_packet, sizeof(dummy_packet), &flow, &should_block));
    EXPECT_TRUE(should_block) << "IPv4-only VPN should block global IPv6 traffic";

    // Verify leak was detected
    privacy_stats_t stats;
    privacy_guards_get_stats(guards, &stats);
    EXPECT_GT(stats.ipv6_leaks_detected, 0) << "IPv6 leak should be detected in IPv4-only VPN";
    EXPECT_GT(stats.ipv6_leaks_blocked, 0) << "IPv6 leak should be blocked with kill switch";
}

TEST_F(IPv6HandlingTest, IPv4OnlyVPN_AllowsLinkLocalIPv6) {
    GTEST_LOG_(INFO) << "Testing IPv4-only VPN allows link-local IPv6 traffic";

    // Configure VPN as IPv4-only with active tunnel
    ASSERT_TRUE(privacy_guards_set_vpn_config(guards, true, false, true));
    ASSERT_TRUE(privacy_guards_enable_kill_switch(guards, true));

    // Test link-local IPv6 traffic (fe80::/10) - should be allowed
    flow_tuple_t flow = create_ipv6_flow("fe80::1", 80, PROTO_TCP);
    
    uint8_t dummy_packet[64] = {0};
    bool should_block = false;

    ASSERT_TRUE(privacy_guards_inspect_packet(guards, dummy_packet, sizeof(dummy_packet), &flow, &should_block));
    EXPECT_FALSE(should_block) << "IPv4-only VPN should allow link-local IPv6 traffic";

    // Verify no leak was detected for link-local
    privacy_stats_t stats;
    privacy_guards_get_stats(guards, &stats);
    EXPECT_EQ(stats.ipv6_leaks_detected, 0) << "Link-local IPv6 should not be flagged as leak";
}

TEST_F(IPv6HandlingTest, IPv4OnlyVPN_AllowsLoopbackIPv6) {
    GTEST_LOG_(INFO) << "Testing IPv4-only VPN allows IPv6 loopback traffic";

    // Configure VPN as IPv4-only with active tunnel
    ASSERT_TRUE(privacy_guards_set_vpn_config(guards, true, false, true));
    ASSERT_TRUE(privacy_guards_enable_kill_switch(guards, true));

    // Test IPv6 loopback traffic (::1) - should be allowed
    flow_tuple_t flow = create_ipv6_flow("::1", 8080, PROTO_TCP);
    
    uint8_t dummy_packet[64] = {0};
    bool should_block = false;

    ASSERT_TRUE(privacy_guards_inspect_packet(guards, dummy_packet, sizeof(dummy_packet), &flow, &should_block));
    EXPECT_FALSE(should_block) << "IPv4-only VPN should allow IPv6 loopback traffic";

    // Verify no leak was detected for loopback
    privacy_stats_t stats;
    privacy_guards_get_stats(guards, &stats);
    EXPECT_EQ(stats.ipv6_leaks_detected, 0) << "IPv6 loopback should not be flagged as leak";
}

TEST_F(IPv6HandlingTest, IPv4OnlyVPN_AllowsLocalMulticast) {
    GTEST_LOG_(INFO) << "Testing IPv4-only VPN allows local IPv6 multicast";

    // Configure VPN as IPv4-only with active tunnel
    ASSERT_TRUE(privacy_guards_set_vpn_config(guards, true, false, true));
    ASSERT_TRUE(privacy_guards_enable_kill_switch(guards, true));

    // Test local multicast IPv6 traffic (ff01::, ff02::) - should be allowed
    flow_tuple_t flow1 = create_ipv6_flow("ff01::1", 5353, PROTO_UDP); // Node-local
    flow_tuple_t flow2 = create_ipv6_flow("ff02::1", 5353, PROTO_UDP); // Link-local
    
    uint8_t dummy_packet[64] = {0};
    bool should_block = false;

    // Test ff01:: (node-local multicast)
    ASSERT_TRUE(privacy_guards_inspect_packet(guards, dummy_packet, sizeof(dummy_packet), &flow1, &should_block));
    EXPECT_FALSE(should_block) << "IPv4-only VPN should allow node-local multicast (ff01::)";

    // Test ff02:: (link-local multicast)
    should_block = false;
    ASSERT_TRUE(privacy_guards_inspect_packet(guards, dummy_packet, sizeof(dummy_packet), &flow2, &should_block));
    EXPECT_FALSE(should_block) << "IPv4-only VPN should allow link-local multicast (ff02::)";

    // Verify no leaks detected for local multicast
    privacy_stats_t stats;
    privacy_guards_get_stats(guards, &stats);
    EXPECT_EQ(stats.ipv6_leaks_detected, 0) << "Local IPv6 multicast should not be flagged as leak";
}

TEST_F(IPv6HandlingTest, IPv4OnlyVPN_BlocksGlobalMulticast) {
    GTEST_LOG_(INFO) << "Testing IPv4-only VPN blocks global IPv6 multicast";

    // Configure VPN as IPv4-only with active tunnel
    ASSERT_TRUE(privacy_guards_set_vpn_config(guards, true, false, true));
    ASSERT_TRUE(privacy_guards_enable_kill_switch(guards, true));

    // Test global multicast IPv6 traffic (ff0e::) - should be blocked
    flow_tuple_t flow = create_ipv6_flow("ff0e::1", 5353, PROTO_UDP); // Global multicast
    
    uint8_t dummy_packet[64] = {0};
    bool should_block = false;

    ASSERT_TRUE(privacy_guards_inspect_packet(guards, dummy_packet, sizeof(dummy_packet), &flow, &should_block));
    EXPECT_TRUE(should_block) << "IPv4-only VPN should block global multicast (ff0e::)";

    // Verify leak was detected
    privacy_stats_t stats;
    privacy_guards_get_stats(guards, &stats);
    EXPECT_GT(stats.ipv6_leaks_detected, 0) << "Global IPv6 multicast should be flagged as leak";
    EXPECT_GT(stats.ipv6_leaks_blocked, 0) << "Global IPv6 multicast should be blocked";
}

TEST_F(IPv6HandlingTest, TunnelInactive_BlocksAllIPv6) {
    GTEST_LOG_(INFO) << "Testing inactive tunnel blocks all IPv6 traffic";

    // Configure VPN as dual-stack but with inactive tunnel
    ASSERT_TRUE(privacy_guards_set_vpn_config(guards, true, true, false));
    ASSERT_TRUE(privacy_guards_enable_kill_switch(guards, true));

    // Test IPv6 traffic when tunnel is inactive - should be blocked
    flow_tuple_t flow = create_ipv6_flow("2001:4860:4860::8888", 53, PROTO_UDP);
    
    uint8_t dummy_packet[64] = {0};
    bool should_block = false;

    ASSERT_TRUE(privacy_guards_inspect_packet(guards, dummy_packet, sizeof(dummy_packet), &flow, &should_block));
    EXPECT_TRUE(should_block) << "Inactive tunnel should block all IPv6 traffic";

    // Verify leak was detected
    privacy_stats_t stats;
    privacy_guards_get_stats(guards, &stats);
    EXPECT_GT(stats.ipv6_leaks_detected, 0) << "IPv6 traffic with inactive tunnel should be flagged as leak";
}

TEST_F(IPv6HandlingTest, TunnelStatusUpdate_AffectsBlocking) {
    GTEST_LOG_(INFO) << "Testing tunnel status updates affect IPv6 blocking";

    // Start with dual-stack VPN and inactive tunnel
    ASSERT_TRUE(privacy_guards_set_vpn_config(guards, true, true, false));
    ASSERT_TRUE(privacy_guards_enable_kill_switch(guards, true));

    flow_tuple_t flow = create_ipv6_flow("2001:4860:4860::8888", 53, PROTO_UDP);
    uint8_t dummy_packet[64] = {0};
    bool should_block = false;

    // With inactive tunnel, IPv6 should be blocked
    ASSERT_TRUE(privacy_guards_inspect_packet(guards, dummy_packet, sizeof(dummy_packet), &flow, &should_block));
    EXPECT_TRUE(should_block) << "IPv6 should be blocked when tunnel inactive";

    // Activate tunnel
    ASSERT_TRUE(privacy_guards_set_tunnel_status(guards, true));

    // Now IPv6 should be allowed
    should_block = false;
    ASSERT_TRUE(privacy_guards_inspect_packet(guards, dummy_packet, sizeof(dummy_packet), &flow, &should_block));
    EXPECT_FALSE(should_block) << "IPv6 should be allowed when tunnel becomes active";
}

TEST_F(IPv6HandlingTest, DisabledIPv6Protection_AllowsAllTraffic) {
    GTEST_LOG_(INFO) << "Testing disabled IPv6 protection allows all traffic";

    // Configure VPN as IPv4-only but disable IPv6 leak protection
    ASSERT_TRUE(privacy_guards_set_vpn_config(guards, true, false, true));
    ASSERT_TRUE(privacy_guards_enable_ipv6_leak_protection(guards, false));

    // Test IPv6 traffic - should be allowed even in IPv4-only VPN
    flow_tuple_t flow = create_ipv6_flow("2001:4860:4860::8888", 53, PROTO_UDP);
    
    uint8_t dummy_packet[64] = {0};
    bool should_block = false;

    ASSERT_TRUE(privacy_guards_inspect_packet(guards, dummy_packet, sizeof(dummy_packet), &flow, &should_block));
    EXPECT_FALSE(should_block) << "Disabled IPv6 protection should allow all IPv6 traffic";

    // Verify no leak was detected
    privacy_stats_t stats;
    privacy_guards_get_stats(guards, &stats);
    EXPECT_EQ(stats.ipv6_leaks_detected, 0) << "No leak should be detected when protection disabled";
}

TEST_F(IPv6HandlingTest, MixedTraffic_HandlesCorrectly) {
    GTEST_LOG_(INFO) << "Testing mixed IPv4/IPv6 traffic handling";

    // Configure VPN as dual-stack with active tunnel
    ASSERT_TRUE(privacy_guards_set_vpn_config(guards, true, true, true));

    uint8_t dummy_packet[64] = {0};
    bool should_block = false;

    // Test IPv4 traffic - should be allowed
    flow_tuple_t ipv4_flow = create_ipv4_flow("8.8.8.8", 53, PROTO_UDP);
    ASSERT_TRUE(privacy_guards_inspect_packet(guards, dummy_packet, sizeof(dummy_packet), &ipv4_flow, &should_block));
    EXPECT_FALSE(should_block) << "IPv4 traffic should be allowed in dual-stack VPN";

    // Test IPv6 traffic - should be allowed
    flow_tuple_t ipv6_flow = create_ipv6_flow("2001:4860:4860::8888", 53, PROTO_UDP);
    should_block = false;
    ASSERT_TRUE(privacy_guards_inspect_packet(guards, dummy_packet, sizeof(dummy_packet), &ipv6_flow, &should_block));
    EXPECT_FALSE(should_block) << "IPv6 traffic should be allowed in dual-stack VPN";

    // Verify no leaks detected
    privacy_stats_t stats;
    privacy_guards_get_stats(guards, &stats);
    EXPECT_EQ(stats.ipv6_leaks_detected, 0) << "No leaks should be detected in dual-stack VPN";
}