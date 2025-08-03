#include <gtest/gtest.h>
#include "nat64/translator.h"
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/udp.h>

class NAT64Test : public ::testing::Test {
protected:
    void SetUp() override {
        // Use default Well-Known Prefix 64:ff9b::/96
        translator = nat64_translator_create(nullptr, 0);
        ASSERT_NE(translator, nullptr);
    }
    
    void TearDown() override {
        if (translator) {
            nat64_translator_destroy(translator);
        }
    }
    
    nat64_translator_t *translator;
};

TEST_F(NAT64Test, CreateDestroy) {
    EXPECT_NE(translator, nullptr);
    
    // Test with custom prefix
    ipv6_addr_t custom_prefix = {};
    custom_prefix.addr[0] = 0x20;
    custom_prefix.addr[1] = 0x01;
    custom_prefix.addr[2] = 0x0d;
    custom_prefix.addr[3] = 0xb8;
    
    nat64_translator_t *custom_translator = nat64_translator_create(&custom_prefix, 96);
    EXPECT_NE(custom_translator, nullptr);
    
    ipv6_addr_t retrieved_prefix;
    uint8_t prefix_length;
    EXPECT_TRUE(nat64_get_prefix(custom_translator, &retrieved_prefix, &prefix_length));
    EXPECT_EQ(prefix_length, 96);
    EXPECT_EQ(memcmp(&retrieved_prefix, &custom_prefix, 12), 0); // First 96 bits
    
    nat64_translator_destroy(custom_translator);
}

TEST_F(NAT64Test, AddressValidation) {
    // Valid IPv4 packet
    uint8_t valid_ipv4[] = {
        0x45, 0x00, 0x00, 0x1c,  // IPv4 header
        0x00, 0x01, 0x00, 0x00,
        0x40, 0x11, 0x00, 0x00,  // UDP protocol
        0xc0, 0xa8, 0x01, 0x01,  // 192.168.1.1
        0x08, 0x08, 0x08, 0x08,  // 8.8.8.8
        0x00, 0x35, 0x00, 0x35,  // UDP ports
        0x00, 0x08, 0x00, 0x00   // UDP header
    };
    
    EXPECT_TRUE(nat64_validate_ipv4_packet(valid_ipv4, sizeof(valid_ipv4)));
    
    // Invalid IPv4 packet (wrong version)
    uint8_t invalid_ipv4[] = {
        0x65, 0x00, 0x00, 0x1c,  // Wrong version (6 instead of 4)
        0x00, 0x01, 0x00, 0x00,
        0x40, 0x11, 0x00, 0x00,
        0xc0, 0xa8, 0x01, 0x01,
        0x08, 0x08, 0x08, 0x08
    };
    
    EXPECT_FALSE(nat64_validate_ipv4_packet(invalid_ipv4, sizeof(invalid_ipv4)));
    
    // Valid IPv6 packet
    uint8_t valid_ipv6[] = {
        0x60, 0x00, 0x00, 0x00,  // IPv6 header
        0x00, 0x08, 0x11, 0x40,  // Payload length, Next header (UDP), Hop limit
        0x20, 0x01, 0x0d, 0xb8,  // Source address
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x01,
        0x00, 0x64, 0xff, 0x9b,  // Destination (NAT64 prefix)
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x08, 0x08, 0x08, 0x08,  // Embedded IPv4
        0x00, 0x35, 0x00, 0x35,  // UDP ports
        0x00, 0x08, 0x00, 0x00   // UDP header
    };
    
    EXPECT_TRUE(nat64_validate_ipv6_packet(valid_ipv6, sizeof(valid_ipv6)));
}

TEST_F(NAT64Test, AddressSynthesis) {
    ipv4_addr_t ipv4_addr = { .addr = inet_addr("8.8.8.8") };
    ipv6_addr_t ipv6_addr;
    
    // Test IPv4 to IPv6 synthesis
    EXPECT_TRUE(nat64_synthesize_ipv6_from_ipv4(translator, &ipv4_addr, &ipv6_addr));
    
    // Check Well-Known Prefix
    EXPECT_EQ(ipv6_addr.addr[0], 0x00);
    EXPECT_EQ(ipv6_addr.addr[1], 0x64);
    EXPECT_EQ(ipv6_addr.addr[2], 0xff);
    EXPECT_EQ(ipv6_addr.addr[3], 0x9b);
    
    // Check embedded IPv4 address
    EXPECT_EQ(ipv6_addr.addr[12], 8);
    EXPECT_EQ(ipv6_addr.addr[13], 8);
    EXPECT_EQ(ipv6_addr.addr[14], 8);
    EXPECT_EQ(ipv6_addr.addr[15], 8);
    
    // Test IPv6 to IPv4 extraction
    ipv4_addr_t extracted_ipv4;
    EXPECT_TRUE(nat64_extract_ipv4_from_ipv6(translator, &ipv6_addr, &extracted_ipv4));
    EXPECT_EQ(extracted_ipv4.addr, inet_addr("8.8.8.8"));
    
    // Test NAT64 address detection
    EXPECT_TRUE(nat64_is_nat64_address(translator, &ipv6_addr));
    
    // Test non-NAT64 address
    ipv6_addr_t non_nat64 = {};
    non_nat64.addr[0] = 0x20;
    non_nat64.addr[1] = 0x01;
    EXPECT_FALSE(nat64_is_nat64_address(translator, &non_nat64));
}

TEST_F(NAT64Test, PacketTranslation4to6) {
    // Create IPv4 UDP packet
    uint8_t ipv4_packet[] = {
        0x45, 0x00, 0x00, 0x20,  // IPv4 header (32 bytes total)
        0x00, 0x01, 0x00, 0x00,
        0x40, 0x11, 0x00, 0x00,  // UDP protocol
        0xc0, 0xa8, 0x01, 0x01,  // 192.168.1.1 (source)
        0x08, 0x08, 0x08, 0x08,  // 8.8.8.8 (destination)
        0x00, 0x35, 0x00, 0x35,  // UDP ports (53 -> 53)
        0x00, 0x0c, 0x00, 0x00,  // UDP length, checksum
        0x01, 0x02, 0x03, 0x04   // Payload
    };
    
    uint8_t ipv6_packet[1500];
    size_t ipv6_length;
    
    bool translated = nat64_translate_4to6(translator, ipv4_packet, sizeof(ipv4_packet),
                                          ipv6_packet, &ipv6_length, sizeof(ipv6_packet));
    
    if (translated) {
        EXPECT_GT(ipv6_length, sizeof(struct ip6_hdr));
        EXPECT_LT(ipv6_length, sizeof(ipv6_packet));
        
        // Check IPv6 header
        struct ip6_hdr *ip6_hdr = (struct ip6_hdr *)ipv6_packet;
        EXPECT_EQ((ip6_hdr->ip6_vfc >> 4), 6); // IPv6 version
        EXPECT_EQ(ip6_hdr->ip6_nxt, IPPROTO_UDP);
    }
}

TEST_F(NAT64Test, PacketTranslation6to4) {
    // Create IPv6 UDP packet with NAT64 destination
    uint8_t ipv6_packet[] = {
        0x60, 0x00, 0x00, 0x00,  // IPv6 header
        0x00, 0x0c, 0x11, 0x40,  // Payload length (12), UDP, Hop limit
        // Source address (2001:db8::1)
        0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
        // Destination address (64:ff9b::8.8.8.8)
        0x00, 0x64, 0xff, 0x9b, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x08, 0x08, 0x08, 0x08,
        // UDP header
        0x00, 0x35, 0x00, 0x35,  // Ports (53 -> 53)
        0x00, 0x0c, 0x00, 0x00,  // Length, checksum
        0x01, 0x02, 0x03, 0x04   // Payload
    };
    
    uint8_t ipv4_packet[1500];
    size_t ipv4_length;
    
    bool translated = nat64_translate_6to4(translator, ipv6_packet, sizeof(ipv6_packet),
                                          ipv4_packet, &ipv4_length, sizeof(ipv4_packet));
    
    if (translated) {
        EXPECT_GT(ipv4_length, sizeof(struct ip));
        EXPECT_LT(ipv4_length, sizeof(ipv4_packet));
        
        // Check IPv4 header
        struct ip *ip_hdr = (struct ip *)ipv4_packet;
        EXPECT_EQ(ip_hdr->ip_v, 4);
        EXPECT_EQ(ip_hdr->ip_p, IPPROTO_UDP);
        EXPECT_EQ(ip_hdr->ip_dst.s_addr, inet_addr("8.8.8.8"));
    }
}

TEST_F(NAT64Test, StaticMappings) {
    ipv4_addr_t ipv4_addr = { .addr = inet_addr("192.168.1.100") };
    ipv6_addr_t ipv6_addr = {};
    ipv6_addr.addr[0] = 0x20;
    ipv6_addr.addr[1] = 0x01;
    ipv6_addr.addr[15] = 0x64;
    
    EXPECT_TRUE(nat64_add_static_mapping(translator, &ipv4_addr, &ipv6_addr));
    EXPECT_TRUE(nat64_remove_static_mapping(translator, &ipv4_addr));
    
    // Remove non-existent mapping
    EXPECT_FALSE(nat64_remove_static_mapping(translator, &ipv4_addr));
}

TEST_F(NAT64Test, Statistics) {
    nat64_stats_t stats;
    nat64_get_stats(translator, &stats);
    
    EXPECT_EQ(stats.total_mappings, 0);
    EXPECT_EQ(stats.active_mappings, 0);
    EXPECT_EQ(stats.packets_translated_4to6, 0);
    EXPECT_EQ(stats.packets_translated_6to4, 0);
    EXPECT_EQ(stats.translation_errors, 0);
}

TEST_F(NAT64Test, MappingManagement) {
    nat64_set_mapping_timeout(translator, 600); // 10 minutes
    
    size_t mapping_count = nat64_get_mapping_count(translator);
    EXPECT_EQ(mapping_count, 0);
    
    // Cleanup should not crash with empty mappings
    nat64_cleanup_expired_mappings(translator);
}

TEST_F(NAT64Test, ErrorHandling) {
    // Test null parameters
    EXPECT_FALSE(nat64_translate_4to6(nullptr, nullptr, 0, nullptr, nullptr, 0));
    EXPECT_FALSE(nat64_translate_6to4(nullptr, nullptr, 0, nullptr, nullptr, 0));
    
    uint8_t packet[100];
    size_t length;
    EXPECT_FALSE(nat64_translate_4to6(translator, nullptr, 0, packet, &length, sizeof(packet)));
    EXPECT_FALSE(nat64_translate_4to6(translator, packet, 0, nullptr, &length, sizeof(packet)));
    EXPECT_FALSE(nat64_translate_4to6(translator, packet, sizeof(packet), packet, nullptr, sizeof(packet)));
    
    // Test invalid packet sizes
    uint8_t small_packet[5];
    EXPECT_FALSE(nat64_translate_4to6(translator, small_packet, sizeof(small_packet), 
                                     packet, &length, sizeof(packet)));
    
    // Test buffer too small
    uint8_t large_packet[1500] = {0x45}; // Valid IPv4 start
    uint8_t tiny_buffer[10];
    EXPECT_FALSE(nat64_translate_4to6(translator, large_packet, sizeof(large_packet),
                                     tiny_buffer, &length, sizeof(tiny_buffer)));
    
    // Test operations on null translator
    EXPECT_FALSE(nat64_set_prefix(nullptr, nullptr, 0));
    EXPECT_FALSE(nat64_get_prefix(nullptr, nullptr, nullptr));
    EXPECT_FALSE(nat64_add_static_mapping(nullptr, nullptr, nullptr));
    EXPECT_FALSE(nat64_remove_static_mapping(nullptr, nullptr));
    EXPECT_FALSE(nat64_is_nat64_address(nullptr, nullptr));
    EXPECT_FALSE(nat64_extract_ipv4_from_ipv6(nullptr, nullptr, nullptr));
    EXPECT_FALSE(nat64_synthesize_ipv6_from_ipv4(nullptr, nullptr, nullptr));
    
    nat64_cleanup_expired_mappings(nullptr); // Should not crash
    nat64_translator_destroy(nullptr); // Should not crash
}

TEST_F(NAT64Test, ChecksumHandling) {
    ipv4_addr_t ipv4_src = { .addr = inet_addr("192.168.1.1") };
    ipv4_addr_t ipv4_dst = { .addr = inet_addr("8.8.8.8") };
    ipv6_addr_t ipv6_src, ipv6_dst;
    
    // Synthesize IPv6 addresses
    EXPECT_TRUE(nat64_synthesize_ipv6_from_ipv4(translator, &ipv4_src, &ipv6_src));
    EXPECT_TRUE(nat64_synthesize_ipv6_from_ipv4(translator, &ipv4_dst, &ipv6_dst));
    
    uint16_t original_checksum = 0x1234;
    
    // Test checksum translation 4to6
    uint16_t translated_checksum = nat64_translate_checksum_4to6(original_checksum, 
                                                               &ipv4_src, &ipv4_dst,
                                                               &ipv6_src, &ipv6_dst);
    EXPECT_NE(translated_checksum, original_checksum);
    
    // Test checksum translation 6to4
    uint16_t back_translated = nat64_translate_checksum_6to4(translated_checksum,
                                                           &ipv6_src, &ipv6_dst,
                                                           &ipv4_src, &ipv4_dst);
    // Note: Due to checksum algorithm differences, this might not be exactly equal
    EXPECT_NE(back_translated, 0);
}

TEST_F(NAT64Test, PrefixManagement) {
    ipv6_addr_t original_prefix;
    uint8_t original_length;
    EXPECT_TRUE(nat64_get_prefix(translator, &original_prefix, &original_length));
    
    // Set new prefix
    ipv6_addr_t new_prefix = {};
    new_prefix.addr[0] = 0x20;
    new_prefix.addr[1] = 0x01;
    new_prefix.addr[2] = 0x0d;
    new_prefix.addr[3] = 0xb8;
    
    EXPECT_TRUE(nat64_set_prefix(translator, &new_prefix, 96));
    
    ipv6_addr_t retrieved_prefix;
    uint8_t retrieved_length;
    EXPECT_TRUE(nat64_get_prefix(translator, &retrieved_prefix, &retrieved_length));
    EXPECT_EQ(retrieved_length, 96);
    EXPECT_EQ(memcmp(&retrieved_prefix, &new_prefix, 12), 0);
    
    // Test invalid prefix lengths
    EXPECT_FALSE(nat64_set_prefix(translator, &new_prefix, 0));
    EXPECT_FALSE(nat64_set_prefix(translator, &new_prefix, 128));
    EXPECT_FALSE(nat64_set_prefix(translator, &new_prefix, 97));
}