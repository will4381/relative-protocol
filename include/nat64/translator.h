#ifndef RELATIVE_VPN_NAT64_TRANSLATOR_H
#define RELATIVE_VPN_NAT64_TRANSLATOR_H

#include "core/types.h"
#include <stdint.h>
#include <stdbool.h>

#define NAT64_PREFIX_LENGTH 96
#define NAT64_WKP_PREFIX "64:ff9b::/96"  // Well-Known Prefix (RFC 6052)

typedef struct nat64_translator nat64_translator_t;

typedef struct nat64_mapping {
    ipv6_addr_t ipv6_addr;
    ipv4_addr_t ipv4_addr;
    uint16_t ipv6_port;
    uint16_t ipv4_port;
    uint8_t protocol;
    uint64_t created_time_ns;
    uint64_t last_activity_ns;
    uint32_t packet_count_v4_to_v6;
    uint32_t packet_count_v6_to_v4;
    uint64_t byte_count_v4_to_v6;
    uint64_t byte_count_v6_to_v4;
    bool active;
} nat64_mapping_t;

typedef struct nat64_stats {
    uint32_t total_mappings;
    uint32_t active_mappings;
    uint32_t packets_translated_4to6;
    uint32_t packets_translated_6to4;
    uint32_t translation_errors;
    uint32_t mapping_timeouts;
    uint64_t bytes_translated_4to6;
    uint64_t bytes_translated_6to4;
} nat64_stats_t;

nat64_translator_t *nat64_translator_create(const ipv6_addr_t *prefix, uint8_t prefix_length);
void nat64_translator_destroy(nat64_translator_t *translator);

bool nat64_translate_4to6(nat64_translator_t *translator, const uint8_t *ipv4_packet, size_t ipv4_length,
                         uint8_t *ipv6_packet, size_t *ipv6_length, size_t max_ipv6_length);

bool nat64_translate_6to4(nat64_translator_t *translator, const uint8_t *ipv6_packet, size_t ipv6_length,
                         uint8_t *ipv4_packet, size_t *ipv4_length, size_t max_ipv4_length);

bool nat64_set_prefix(nat64_translator_t *translator, const ipv6_addr_t *prefix, uint8_t prefix_length);
bool nat64_get_prefix(nat64_translator_t *translator, ipv6_addr_t *prefix, uint8_t *prefix_length);

bool nat64_add_static_mapping(nat64_translator_t *translator, const ipv4_addr_t *ipv4_addr, 
                             const ipv6_addr_t *ipv6_addr);
bool nat64_remove_static_mapping(nat64_translator_t *translator, const ipv4_addr_t *ipv4_addr);

void nat64_set_mapping_timeout(nat64_translator_t *translator, uint32_t timeout_seconds);
void nat64_cleanup_expired_mappings(nat64_translator_t *translator);

bool nat64_is_nat64_address(nat64_translator_t *translator, const ipv6_addr_t *ipv6_addr);
bool nat64_extract_ipv4_from_ipv6(nat64_translator_t *translator, const ipv6_addr_t *ipv6_addr, 
                                 ipv4_addr_t *ipv4_addr);
bool nat64_synthesize_ipv6_from_ipv4(nat64_translator_t *translator, const ipv4_addr_t *ipv4_addr,
                                    ipv6_addr_t *ipv6_addr);

size_t nat64_get_mapping_count(nat64_translator_t *translator);
bool nat64_get_mapping(nat64_translator_t *translator, size_t index, nat64_mapping_t *mapping);
void nat64_get_stats(nat64_translator_t *translator, nat64_stats_t *stats);

bool nat64_validate_ipv4_packet(const uint8_t *packet, size_t length);
bool nat64_validate_ipv6_packet(const uint8_t *packet, size_t length);

uint16_t nat64_translate_checksum_4to6(uint16_t ipv4_checksum, const ipv4_addr_t *ipv4_src, 
                                      const ipv4_addr_t *ipv4_dst, const ipv6_addr_t *ipv6_src, 
                                      const ipv6_addr_t *ipv6_dst);

uint16_t nat64_translate_checksum_6to4(uint16_t ipv6_checksum, const ipv6_addr_t *ipv6_src, 
                                      const ipv6_addr_t *ipv6_dst, const ipv4_addr_t *ipv4_src, 
                                      const ipv4_addr_t *ipv4_dst);

void nat64_print_mapping(const nat64_mapping_t *mapping);
void nat64_print_stats(const nat64_stats_t *stats);

#endif