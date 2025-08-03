#include "nat64/translator.h"
#include "core/logging.h"
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/icmp6.h>
#include <arpa/inet.h>

#define MAX_NAT64_MAPPINGS 1024
#define NAT64_DEFAULT_TIMEOUT 300 // 5 minutes
#define NAT64_TCP_TIMEOUT 7200    // 2 hours
#define NAT64_UDP_TIMEOUT 300     // 5 minutes
#define NAT64_ICMP_TIMEOUT 60     // 1 minute

struct nat64_translator {
    ipv6_addr_t prefix;
    uint8_t prefix_length;
    nat64_mapping_t mappings[MAX_NAT64_MAPPINGS];
    size_t mapping_count;
    uint32_t mapping_timeout_seconds;
    uint16_t next_port;
    pthread_mutex_t mutex;
    nat64_stats_t stats;
};

static nat64_mapping_t *nat64_find_mapping_4to6(nat64_translator_t *translator, 
                                               const ipv4_addr_t *ipv4_addr, uint16_t port, uint8_t protocol);
static nat64_mapping_t *nat64_find_mapping_6to4(nat64_translator_t *translator, 
                                               const ipv6_addr_t *ipv6_addr, uint16_t port, uint8_t protocol);

static nat64_mapping_t *nat64_find_mapping_6to4(nat64_translator_t *translator, 
                                               const ipv6_addr_t *ipv6_addr, uint16_t port, uint8_t protocol) {
    if (!translator || !ipv6_addr) return NULL;
    
    pthread_mutex_lock(&translator->mutex);
    
    for (size_t i = 0; i < translator->mapping_count; i++) {
        nat64_mapping_t *mapping = &translator->mappings[i];
        if (mapping->active && mapping->protocol == protocol &&
            mapping->ipv6_port == port &&
            memcmp(&mapping->ipv6_addr, ipv6_addr, sizeof(ipv6_addr_t)) == 0) {
            pthread_mutex_unlock(&translator->mutex);
            return mapping;
        }
    }
    
    pthread_mutex_unlock(&translator->mutex);
    return NULL;
}
static nat64_mapping_t *nat64_create_mapping(nat64_translator_t *translator, 
                                            const ipv4_addr_t *ipv4_addr, const ipv6_addr_t *ipv6_addr,
                                            uint16_t ipv4_port, uint16_t ipv6_port, uint8_t protocol);
static bool nat64_translate_tcp_4to6(nat64_translator_t *translator, const struct ip *ipv4_hdr, 
                                    const struct tcphdr *tcp_hdr, const uint8_t *payload, size_t payload_len,
                                    uint8_t *ipv6_packet, size_t *ipv6_length, size_t max_length);
static bool nat64_translate_udp_4to6(nat64_translator_t *translator, const struct ip *ipv4_hdr, 
                                    const struct udphdr *udp_hdr, const uint8_t *payload, size_t payload_len,
                                    uint8_t *ipv6_packet, size_t *ipv6_length, size_t max_length);
static bool nat64_translate_tcp_6to4(nat64_translator_t *translator, const struct ip6_hdr *ipv6_hdr, 
                                    const struct tcphdr *tcp_hdr, const uint8_t *payload, size_t payload_len,
                                    uint8_t *ipv4_packet, size_t *ipv4_length, size_t max_length);
static bool nat64_translate_udp_6to4(nat64_translator_t *translator, const struct ip6_hdr *ipv6_hdr, 
                                    const struct udphdr *udp_hdr, const uint8_t *payload, size_t payload_len,
                                    uint8_t *ipv4_packet, size_t *ipv4_length, size_t max_length);
static uint16_t nat64_calculate_checksum(const void *data, size_t len);

nat64_translator_t *nat64_translator_create(const ipv6_addr_t *prefix, uint8_t prefix_length) {
    nat64_translator_t *translator = calloc(1, sizeof(nat64_translator_t));
    if (!translator) {
        LOG_ERROR("Failed to allocate NAT64 translator");
        return NULL;
    }
    
    if (pthread_mutex_init(&translator->mutex, NULL) != 0) {
        LOG_ERROR("Failed to initialize NAT64 translator mutex");
        free(translator);
        return NULL;
    }
    
    if (prefix && prefix_length > 0 && prefix_length <= 96) {
        translator->prefix = *prefix;
        translator->prefix_length = prefix_length;
    } else {
        // Use Well-Known Prefix 64:ff9b::/96
        memset(&translator->prefix, 0, sizeof(ipv6_addr_t));
        translator->prefix.addr[0] = 0x00;
        translator->prefix.addr[1] = 0x64;
        translator->prefix.addr[2] = 0xff;
        translator->prefix.addr[3] = 0x9b;
        translator->prefix_length = 96;
    }
    
    translator->mapping_timeout_seconds = NAT64_DEFAULT_TIMEOUT;
    translator->next_port = 10000;
    
    LOG_INFO("NAT64 translator created with prefix length %d", translator->prefix_length);
    return translator;
}

void nat64_translator_destroy(nat64_translator_t *translator) {
    if (!translator) return;
    
    pthread_mutex_lock(&translator->mutex);
    
    for (size_t i = 0; i < translator->mapping_count; i++) {
        translator->mappings[i].active = false;
    }
    translator->mapping_count = 0;
    
    pthread_mutex_unlock(&translator->mutex);
    pthread_mutex_destroy(&translator->mutex);
    
    free(translator);
    LOG_INFO("NAT64 translator destroyed");
}

bool nat64_translate_4to6(nat64_translator_t *translator, const uint8_t *ipv4_packet, size_t ipv4_length,
                         uint8_t *ipv6_packet, size_t *ipv6_length, size_t max_ipv6_length) {
    if (!translator || !ipv4_packet || !ipv6_packet || !ipv6_length || 
        ipv4_length < sizeof(struct ip) || max_ipv6_length < sizeof(struct ip6_hdr)) {
        return false;
    }
    
    if (!nat64_validate_ipv4_packet(ipv4_packet, ipv4_length)) {
        LOG_ERROR("Invalid IPv4 packet for NAT64 translation");
        translator->stats.translation_errors++;
        return false;
    }
    
    pthread_mutex_lock(&translator->mutex);
    
    const struct ip *ipv4_hdr = (const struct ip *)ipv4_packet;
    const uint8_t *payload = ipv4_packet + (ipv4_hdr->ip_hl * 4);
    size_t payload_len = ipv4_length - (ipv4_hdr->ip_hl * 4);
    
    bool success = false;
    
    switch (ipv4_hdr->ip_p) {
        case IPPROTO_TCP:
            if (payload_len >= sizeof(struct tcphdr)) {
                const struct tcphdr *tcp_hdr = (const struct tcphdr *)payload;
                success = nat64_translate_tcp_4to6(translator, ipv4_hdr, tcp_hdr, 
                                                 payload + sizeof(struct tcphdr), 
                                                 payload_len - sizeof(struct tcphdr),
                                                 ipv6_packet, ipv6_length, max_ipv6_length);
            }
            break;
            
        case IPPROTO_UDP:
            if (payload_len >= sizeof(struct udphdr)) {
                const struct udphdr *udp_hdr = (const struct udphdr *)payload;
                success = nat64_translate_udp_4to6(translator, ipv4_hdr, udp_hdr,
                                                 payload + sizeof(struct udphdr),
                                                 payload_len - sizeof(struct udphdr),
                                                 ipv6_packet, ipv6_length, max_ipv6_length);
            }
            break;
            
        default:
            LOG_DEBUG("Unsupported protocol %d for NAT64 4to6 translation", ipv4_hdr->ip_p);
            translator->stats.translation_errors++;
            break;
    }
    
    if (success) {
        translator->stats.packets_translated_4to6++;
        translator->stats.bytes_translated_4to6 += ipv4_length;
    }
    
    pthread_mutex_unlock(&translator->mutex);
    return success;
}

bool nat64_translate_6to4(nat64_translator_t *translator, const uint8_t *ipv6_packet, size_t ipv6_length,
                         uint8_t *ipv4_packet, size_t *ipv4_length, size_t max_ipv4_length) {
    if (!translator || !ipv6_packet || !ipv4_packet || !ipv4_length || 
        ipv6_length < sizeof(struct ip6_hdr) || max_ipv4_length < sizeof(struct ip)) {
        return false;
    }
    
    if (!nat64_validate_ipv6_packet(ipv6_packet, ipv6_length)) {
        LOG_ERROR("Invalid IPv6 packet for NAT64 translation");
        translator->stats.translation_errors++;
        return false;
    }
    
    pthread_mutex_lock(&translator->mutex);
    
    const struct ip6_hdr *ipv6_hdr = (const struct ip6_hdr *)ipv6_packet;
    
    if (!nat64_is_nat64_address(translator, (const ipv6_addr_t *)&ipv6_hdr->ip6_dst)) {
        LOG_DEBUG("IPv6 destination is not a NAT64 address");
        pthread_mutex_unlock(&translator->mutex);
        return false;
    }
    
    const uint8_t *payload = ipv6_packet + sizeof(struct ip6_hdr);
    size_t payload_len = ipv6_length - sizeof(struct ip6_hdr);
    
    bool success = false;
    
    switch (ipv6_hdr->ip6_nxt) {
        case IPPROTO_TCP:
            if (payload_len >= sizeof(struct tcphdr)) {
                const struct tcphdr *tcp_hdr = (const struct tcphdr *)payload;
                success = nat64_translate_tcp_6to4(translator, ipv6_hdr, tcp_hdr,
                                                 payload + sizeof(struct tcphdr),
                                                 payload_len - sizeof(struct tcphdr),
                                                 ipv4_packet, ipv4_length, max_ipv4_length);
            }
            break;
            
        case IPPROTO_UDP:
            if (payload_len >= sizeof(struct udphdr)) {
                const struct udphdr *udp_hdr = (const struct udphdr *)payload;
                success = nat64_translate_udp_6to4(translator, ipv6_hdr, udp_hdr,
                                                 payload + sizeof(struct udphdr),
                                                 payload_len - sizeof(struct udphdr),
                                                 ipv4_packet, ipv4_length, max_ipv4_length);
            }
            break;
            
        default:
            LOG_DEBUG("Unsupported protocol %d for NAT64 6to4 translation", ipv6_hdr->ip6_nxt);
            translator->stats.translation_errors++;
            break;
    }
    
    if (success) {
        translator->stats.packets_translated_6to4++;
        translator->stats.bytes_translated_6to4 += ipv6_length;
    }
    
    pthread_mutex_unlock(&translator->mutex);
    return success;
}

bool nat64_is_nat64_address(nat64_translator_t *translator, const ipv6_addr_t *ipv6_addr) {
    if (!translator || !ipv6_addr) return false;
    
    int prefix_bytes = translator->prefix_length / 8;
    int prefix_bits = translator->prefix_length % 8;
    
    if (memcmp(ipv6_addr->addr, translator->prefix.addr, prefix_bytes) != 0) {
        return false;
    }
    
    if (prefix_bits > 0) {
        uint8_t mask = 0xFF << (8 - prefix_bits);
        if ((ipv6_addr->addr[prefix_bytes] & mask) != (translator->prefix.addr[prefix_bytes] & mask)) {
            return false;
        }
    }
    
    return true;
}

bool nat64_extract_ipv4_from_ipv6(nat64_translator_t *translator, const ipv6_addr_t *ipv6_addr, 
                                 ipv4_addr_t *ipv4_addr) {
    if (!translator || !ipv6_addr || !ipv4_addr) return false;
    
    if (!nat64_is_nat64_address(translator, ipv6_addr)) return false;
    
    int ipv4_offset = translator->prefix_length / 8;
    
    if (ipv4_offset + 4 > 16) return false;
    
    memcpy(&ipv4_addr->addr, &ipv6_addr->addr[ipv4_offset], 4);
    return true;
}

bool nat64_synthesize_ipv6_from_ipv4(nat64_translator_t *translator, const ipv4_addr_t *ipv4_addr,
                                    ipv6_addr_t *ipv6_addr) {
    if (!translator || !ipv4_addr || !ipv6_addr) return false;
    
    memcpy(ipv6_addr, &translator->prefix, sizeof(ipv6_addr_t));
    
    int ipv4_offset = translator->prefix_length / 8;
    
    if (ipv4_offset + 4 > 16) return false;
    
    memcpy(&ipv6_addr->addr[ipv4_offset], &ipv4_addr->addr, 4);
    return true;
}

static bool nat64_translate_tcp_4to6(nat64_translator_t *translator, const struct ip *ipv4_hdr, 
                                    const struct tcphdr *tcp_hdr, const uint8_t *payload, size_t payload_len,
                                    uint8_t *ipv6_packet, size_t *ipv6_length, size_t max_length) {
    
    ipv4_addr_t src_ipv4 = { .addr = ipv4_hdr->ip_src.s_addr };
    ipv4_addr_t dst_ipv4 = { .addr = ipv4_hdr->ip_dst.s_addr };
    
    ipv6_addr_t src_ipv6, dst_ipv6;
    if (!nat64_synthesize_ipv6_from_ipv4(translator, &src_ipv4, &src_ipv6) ||
        !nat64_synthesize_ipv6_from_ipv4(translator, &dst_ipv4, &dst_ipv6)) {
        return false;
    }
    
    nat64_mapping_t *mapping = nat64_find_mapping_4to6(translator, &src_ipv4, 
                                                      ntohs(tcp_hdr->th_sport), IPPROTO_TCP);
    
    if (!mapping) {
        mapping = nat64_create_mapping(translator, &src_ipv4, &src_ipv6,
                                     ntohs(tcp_hdr->th_sport), ntohs(tcp_hdr->th_sport), IPPROTO_TCP);
        if (!mapping) return false;
    }
    
    size_t total_length = sizeof(struct ip6_hdr) + sizeof(struct tcphdr) + payload_len;
    if (total_length > max_length) return false;
    
    struct ip6_hdr *ipv6_hdr = (struct ip6_hdr *)ipv6_packet;
    memset(ipv6_hdr, 0, sizeof(struct ip6_hdr));
    
    ipv6_hdr->ip6_vfc = 0x60;
    ipv6_hdr->ip6_plen = htons(sizeof(struct tcphdr) + payload_len);
    ipv6_hdr->ip6_nxt = IPPROTO_TCP;
    ipv6_hdr->ip6_hlim = 64;
    memcpy(&ipv6_hdr->ip6_src, &src_ipv6, sizeof(ipv6_addr_t));
    memcpy(&ipv6_hdr->ip6_dst, &dst_ipv6, sizeof(ipv6_addr_t));
    
    struct tcphdr *new_tcp_hdr = (struct tcphdr *)(ipv6_packet + sizeof(struct ip6_hdr));
    memcpy(new_tcp_hdr, tcp_hdr, sizeof(struct tcphdr));
    
    if (payload_len > 0) {
        memcpy(ipv6_packet + sizeof(struct ip6_hdr) + sizeof(struct tcphdr), payload, payload_len);
    }
    
    new_tcp_hdr->th_sum = 0;
    new_tcp_hdr->th_sum = nat64_translate_checksum_4to6(tcp_hdr->th_sum, &src_ipv4, &dst_ipv4, 
                                                       &src_ipv6, &dst_ipv6);
    
    *ipv6_length = total_length;
    
    mapping->last_activity_ns = clock_gettime_nsec_np(CLOCK_MONOTONIC);
    mapping->packet_count_v4_to_v6++;
    mapping->byte_count_v4_to_v6 += total_length;
    
    return true;
}

static bool nat64_translate_udp_4to6(nat64_translator_t *translator, const struct ip *ipv4_hdr, 
                                    const struct udphdr *udp_hdr, const uint8_t *payload, size_t payload_len,
                                    uint8_t *ipv6_packet, size_t *ipv6_length, size_t max_length) {
    
    ipv4_addr_t src_ipv4 = { .addr = ipv4_hdr->ip_src.s_addr };
    ipv4_addr_t dst_ipv4 = { .addr = ipv4_hdr->ip_dst.s_addr };
    
    ipv6_addr_t src_ipv6, dst_ipv6;
    if (!nat64_synthesize_ipv6_from_ipv4(translator, &src_ipv4, &src_ipv6) ||
        !nat64_synthesize_ipv6_from_ipv4(translator, &dst_ipv4, &dst_ipv6)) {
        return false;
    }
    
    nat64_mapping_t *mapping = nat64_find_mapping_4to6(translator, &src_ipv4, 
                                                      ntohs(udp_hdr->uh_sport), IPPROTO_UDP);
    
    if (!mapping) {
        mapping = nat64_create_mapping(translator, &src_ipv4, &src_ipv6,
                                     ntohs(udp_hdr->uh_sport), ntohs(udp_hdr->uh_sport), IPPROTO_UDP);
        if (!mapping) return false;
    }
    
    size_t total_length = sizeof(struct ip6_hdr) + sizeof(struct udphdr) + payload_len;
    if (total_length > max_length) return false;
    
    struct ip6_hdr *ipv6_hdr = (struct ip6_hdr *)ipv6_packet;
    memset(ipv6_hdr, 0, sizeof(struct ip6_hdr));
    
    ipv6_hdr->ip6_vfc = 0x60;
    ipv6_hdr->ip6_plen = htons(sizeof(struct udphdr) + payload_len);
    ipv6_hdr->ip6_nxt = IPPROTO_UDP;
    ipv6_hdr->ip6_hlim = 64;
    memcpy(&ipv6_hdr->ip6_src, &src_ipv6, sizeof(ipv6_addr_t));
    memcpy(&ipv6_hdr->ip6_dst, &dst_ipv6, sizeof(ipv6_addr_t));
    
    struct udphdr *new_udp_hdr = (struct udphdr *)(ipv6_packet + sizeof(struct ip6_hdr));
    memcpy(new_udp_hdr, udp_hdr, sizeof(struct udphdr));
    
    if (payload_len > 0) {
        memcpy(ipv6_packet + sizeof(struct ip6_hdr) + sizeof(struct udphdr), payload, payload_len);
    }
    
    new_udp_hdr->uh_sum = 0;
    new_udp_hdr->uh_sum = nat64_translate_checksum_4to6(udp_hdr->uh_sum, &src_ipv4, &dst_ipv4, 
                                                       &src_ipv6, &dst_ipv6);
    
    *ipv6_length = total_length;
    
    mapping->last_activity_ns = clock_gettime_nsec_np(CLOCK_MONOTONIC);
    mapping->packet_count_v4_to_v6++;
    mapping->byte_count_v4_to_v6 += total_length;
    
    return true;
}

static nat64_mapping_t *nat64_find_mapping_4to6(nat64_translator_t *translator, 
                                               const ipv4_addr_t *ipv4_addr, uint16_t port, uint8_t protocol) {
    for (size_t i = 0; i < translator->mapping_count; i++) {
        nat64_mapping_t *mapping = &translator->mappings[i];
        if (mapping->active && 
            mapping->ipv4_addr.addr == ipv4_addr->addr &&
            mapping->ipv4_port == port &&
            mapping->protocol == protocol) {
            return mapping;
        }
    }
    return NULL;
}

static nat64_mapping_t *nat64_create_mapping(nat64_translator_t *translator, 
                                            const ipv4_addr_t *ipv4_addr, const ipv6_addr_t *ipv6_addr,
                                            uint16_t ipv4_port, uint16_t ipv6_port, uint8_t protocol) {
    if (translator->mapping_count >= MAX_NAT64_MAPPINGS) {
        LOG_WARN("NAT64 mapping table full");
        return NULL;
    }
    
    nat64_mapping_t *mapping = &translator->mappings[translator->mapping_count++];
    memset(mapping, 0, sizeof(nat64_mapping_t));
    
    mapping->ipv4_addr = *ipv4_addr;
    mapping->ipv6_addr = *ipv6_addr;
    mapping->ipv4_port = ipv4_port;
    mapping->ipv6_port = ipv6_port;
    mapping->protocol = protocol;
    mapping->created_time_ns = clock_gettime_nsec_np(CLOCK_MONOTONIC);
    mapping->last_activity_ns = mapping->created_time_ns;
    mapping->active = true;
    
    translator->stats.total_mappings++;
    translator->stats.active_mappings++;
    
    return mapping;
}

bool nat64_validate_ipv4_packet(const uint8_t *packet, size_t length) {
    if (!packet || length < sizeof(struct ip)) return false;
    
    const struct ip *hdr = (const struct ip *)packet;
    
    if (hdr->ip_v != 4) return false;
    if (hdr->ip_hl < 5) return false;
    if (ntohs(hdr->ip_len) > length) return false;
    
    return true;
}

bool nat64_validate_ipv6_packet(const uint8_t *packet, size_t length) {
    if (!packet || length < sizeof(struct ip6_hdr)) return false;
    
    const struct ip6_hdr *hdr = (const struct ip6_hdr *)packet;
    
    if ((hdr->ip6_vfc >> 4) != 6) return false;
    if (sizeof(struct ip6_hdr) + ntohs(hdr->ip6_plen) > length) return false;
    
    return true;
}

static uint16_t nat64_calculate_checksum(const void *data, size_t len) {
    const uint16_t *buf = (const uint16_t *)data;
    uint32_t sum = 0;
    
    while (len > 1) {
        sum += *buf++;
        len -= 2;
    }
    
    if (len == 1) {
        sum += *(const uint8_t*)buf << 8;
    }
    
    while (sum >> 16) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    
    return ~sum;
}

static bool nat64_translate_tcp_6to4(nat64_translator_t *translator, const struct ip6_hdr *ipv6_hdr, 
                                    const struct tcphdr *tcp_hdr, const uint8_t *payload, size_t payload_len,
                                    uint8_t *ipv4_packet, size_t *ipv4_length, size_t max_length) {
    if (!translator || !ipv6_hdr || !tcp_hdr || !ipv4_packet || !ipv4_length) {
        return false;
    }
    
    // Extract IPv4 address from IPv6 (RFC 6052)
    ipv4_addr_t ipv4_addr;
    if (!nat64_extract_ipv4_from_ipv6(translator, (const ipv6_addr_t*)&ipv6_hdr->ip6_dst, &ipv4_addr)) {
        return false;
    }
    
    // Find or create mapping
    nat64_mapping_t *mapping = nat64_find_mapping_6to4(translator, 
                                                      (const ipv6_addr_t*)&ipv6_hdr->ip6_src, 
                                                      ntohs(tcp_hdr->th_sport), 
                                                      IPPROTO_TCP);
    if (!mapping) {
        mapping = nat64_create_mapping(translator, &ipv4_addr, (const ipv6_addr_t*)&ipv6_hdr->ip6_src,
                                     ntohs(tcp_hdr->th_dport), ntohs(tcp_hdr->th_sport), IPPROTO_TCP);
        if (!mapping) return false;
    }
    
    // Build IPv4 packet
    size_t total_length = sizeof(struct ip) + sizeof(struct tcphdr) + payload_len;
    if (total_length > max_length) {
        return false;
    }
    
    struct ip *ip_hdr = (struct ip *)ipv4_packet;
    memset(ip_hdr, 0, sizeof(struct ip));
    ip_hdr->ip_v = 4;
    ip_hdr->ip_hl = 5;
    ip_hdr->ip_len = htons(total_length);
    ip_hdr->ip_id = htons(rand() & 0xFFFF);
    ip_hdr->ip_ttl = ipv6_hdr->ip6_hlim;
    ip_hdr->ip_p = IPPROTO_TCP;
    ip_hdr->ip_src.s_addr = mapping->ipv4_addr.addr;
    ip_hdr->ip_dst.s_addr = ipv4_addr.addr;
    
    // Copy TCP header and payload
    struct tcphdr *new_tcp_hdr = (struct tcphdr *)(ipv4_packet + sizeof(struct ip));
    memcpy(new_tcp_hdr, tcp_hdr, sizeof(struct tcphdr));
    new_tcp_hdr->th_sport = htons(mapping->ipv4_port);
    
    if (payload_len > 0) {
        memcpy(ipv4_packet + sizeof(struct ip) + sizeof(struct tcphdr), payload, payload_len);
    }
    
    // Calculate checksums
    ip_hdr->ip_sum = 0;
    ip_hdr->ip_sum = nat64_calculate_checksum(ip_hdr, sizeof(struct ip));
    
    new_tcp_hdr->th_sum = 0;
    // TCP checksum calculation would be more complex - simplified here
    
    *ipv4_length = total_length;
    mapping->last_activity_ns = clock_gettime_nsec_np(CLOCK_MONOTONIC);
    translator->stats.packets_translated_6to4++;
    
    return true;
}

static bool nat64_translate_udp_6to4(nat64_translator_t *translator, const struct ip6_hdr *ipv6_hdr, 
                                    const struct udphdr *udp_hdr, const uint8_t *payload, size_t payload_len,
                                    uint8_t *ipv4_packet, size_t *ipv4_length, size_t max_length) {
    if (!translator || !ipv6_hdr || !udp_hdr || !ipv4_packet || !ipv4_length) {
        return false;
    }
    
    // Extract IPv4 address from IPv6 (RFC 6052)
    ipv4_addr_t ipv4_addr;
    if (!nat64_extract_ipv4_from_ipv6(translator, (const ipv6_addr_t*)&ipv6_hdr->ip6_dst, &ipv4_addr)) {
        return false;
    }
    
    // Find or create mapping
    nat64_mapping_t *mapping = nat64_find_mapping_6to4(translator, 
                                                      (const ipv6_addr_t*)&ipv6_hdr->ip6_src, 
                                                      ntohs(udp_hdr->uh_sport), 
                                                      IPPROTO_UDP);
    if (!mapping) {
        mapping = nat64_create_mapping(translator, &ipv4_addr, (const ipv6_addr_t*)&ipv6_hdr->ip6_src,
                                     ntohs(udp_hdr->uh_dport), ntohs(udp_hdr->uh_sport), IPPROTO_UDP);
        if (!mapping) return false;
    }
    
    // Build IPv4 packet
    size_t total_length = sizeof(struct ip) + sizeof(struct udphdr) + payload_len;
    if (total_length > max_length) {
        return false;
    }
    
    struct ip *ip_hdr = (struct ip *)ipv4_packet;
    memset(ip_hdr, 0, sizeof(struct ip));
    ip_hdr->ip_v = 4;
    ip_hdr->ip_hl = 5;
    ip_hdr->ip_len = htons(total_length);
    ip_hdr->ip_id = htons(rand() & 0xFFFF);
    ip_hdr->ip_ttl = ipv6_hdr->ip6_hlim;
    ip_hdr->ip_p = IPPROTO_UDP;
    ip_hdr->ip_src.s_addr = mapping->ipv4_addr.addr;
    ip_hdr->ip_dst.s_addr = ipv4_addr.addr;
    
    // Copy UDP header and payload
    struct udphdr *new_udp_hdr = (struct udphdr *)(ipv4_packet + sizeof(struct ip));
    memcpy(new_udp_hdr, udp_hdr, sizeof(struct udphdr));
    new_udp_hdr->uh_sport = htons(mapping->ipv4_port);
    
    if (payload_len > 0) {
        memcpy(ipv4_packet + sizeof(struct ip) + sizeof(struct udphdr), payload, payload_len);
    }
    
    // Calculate checksums
    ip_hdr->ip_sum = 0;
    ip_hdr->ip_sum = nat64_calculate_checksum(ip_hdr, sizeof(struct ip));
    
    new_udp_hdr->uh_sum = 0;
    // UDP checksum calculation would be more complex - simplified here
    
    *ipv4_length = total_length;
    mapping->last_activity_ns = clock_gettime_nsec_np(CLOCK_MONOTONIC);
    translator->stats.packets_translated_6to4++;
    
    return true;
}

// PRODUCTION FIX: Implement missing NAT64 checksum translation functions
uint16_t nat64_translate_checksum_4to6(uint16_t ipv4_checksum, const ipv4_addr_t *ipv4_src, 
                                      const ipv4_addr_t *ipv4_dst, const ipv6_addr_t *ipv6_src, 
                                      const ipv6_addr_t *ipv6_dst) {
    if (!ipv4_src || !ipv4_dst || !ipv6_src || !ipv6_dst) {
        return ipv4_checksum;  // Return original if invalid parameters
    }
    
    // RFC 6052: Checksum adjustment for IPv4 to IPv6 translation
    // We need to adjust the checksum by removing IPv4 addresses and adding IPv6 addresses
    uint32_t checksum = ~ipv4_checksum & 0xFFFF;
    
    // Remove IPv4 source address contribution (32-bit)
    uint32_t ipv4_src_addr = ntohl(ipv4_src->addr);
    checksum -= (ipv4_src_addr >> 16) & 0xFFFF;
    checksum -= ipv4_src_addr & 0xFFFF;
    
    // Remove IPv4 destination address contribution (32-bit)  
    uint32_t ipv4_dst_addr = ntohl(ipv4_dst->addr);
    checksum -= (ipv4_dst_addr >> 16) & 0xFFFF;
    checksum -= ipv4_dst_addr & 0xFFFF;
    
    // Add IPv6 source address contribution (128-bit)
    for (int i = 0; i < 8; i++) {
        uint16_t word = ntohs(((uint16_t*)ipv6_src->addr)[i]);
        checksum += word;
    }
    
    // Add IPv6 destination address contribution (128-bit)
    for (int i = 0; i < 8; i++) {
        uint16_t word = ntohs(((uint16_t*)ipv6_dst->addr)[i]);
        checksum += word;
    }
    
    // Handle carry bits
    while (checksum >> 16) {
        checksum = (checksum & 0xFFFF) + (checksum >> 16);
    }
    
    return ~checksum & 0xFFFF;
}

uint16_t nat64_translate_checksum_6to4(uint16_t ipv6_checksum, const ipv6_addr_t *ipv6_src, 
                                      const ipv6_addr_t *ipv6_dst, const ipv4_addr_t *ipv4_src, 
                                      const ipv4_addr_t *ipv4_dst) {
    if (!ipv6_src || !ipv6_dst || !ipv4_src || !ipv4_dst) {
        return ipv6_checksum;  // Return original if invalid parameters
    }
    
    // RFC 6052: Checksum adjustment for IPv6 to IPv4 translation
    // We need to adjust the checksum by removing IPv6 addresses and adding IPv4 addresses
    uint32_t checksum = ~ipv6_checksum & 0xFFFF;
    
    // Remove IPv6 source address contribution (128-bit)
    for (int i = 0; i < 8; i++) {
        uint16_t word = ntohs(((uint16_t*)ipv6_src->addr)[i]);
        checksum -= word;
    }
    
    // Remove IPv6 destination address contribution (128-bit)  
    for (int i = 0; i < 8; i++) {
        uint16_t word = ntohs(((uint16_t*)ipv6_dst->addr)[i]);
        checksum -= word;
    }
    
    // Add IPv4 source address contribution (32-bit)
    uint32_t ipv4_src_addr = ntohl(ipv4_src->addr);
    checksum += (ipv4_src_addr >> 16) & 0xFFFF;
    checksum += ipv4_src_addr & 0xFFFF;
    
    // Add IPv4 destination address contribution (32-bit)
    uint32_t ipv4_dst_addr = ntohl(ipv4_dst->addr);
    checksum += (ipv4_dst_addr >> 16) & 0xFFFF;
    checksum += ipv4_dst_addr & 0xFFFF;
    
    // Handle carry bits and underflow
    while (checksum >> 16) {
        checksum = (checksum & 0xFFFF) + (checksum >> 16);
    }
    
    return ~checksum & 0xFFFF;
}

// PRODUCTION FIX: Add missing NAT64 stats function
void nat64_get_stats(nat64_translator_t *translator, nat64_stats_t *stats) {
    if (!translator || !stats) {
        return;
    }
    
    pthread_mutex_lock(&translator->mutex);
    
    // Copy current statistics
    memcpy(stats, &translator->stats, sizeof(nat64_stats_t));
    
    // Update active mapping count
    stats->active_mappings = 0;
    for (size_t i = 0; i < translator->mapping_count; i++) {
        if (translator->mappings[i].active) {
            stats->active_mappings++;
        }
    }
    
    stats->total_mappings = translator->mapping_count;
    
    pthread_mutex_unlock(&translator->mutex);
}

// PRODUCTION FIX: Add missing NAT64 functions required by unit tests
bool nat64_set_prefix(nat64_translator_t *translator, const ipv6_addr_t *prefix, uint8_t prefix_length) {
    if (!translator || !prefix || prefix_length > 128) {
        return false;
    }
    
    pthread_mutex_lock(&translator->mutex);
    memcpy(&translator->prefix, prefix, sizeof(ipv6_addr_t));
    translator->prefix_length = prefix_length;
    pthread_mutex_unlock(&translator->mutex);
    
    return true;
}

bool nat64_get_prefix(nat64_translator_t *translator, ipv6_addr_t *prefix, uint8_t *prefix_length) {
    if (!translator || !prefix || !prefix_length) {
        return false;
    }
    
    pthread_mutex_lock(&translator->mutex);
    memcpy(prefix, &translator->prefix, sizeof(ipv6_addr_t));
    *prefix_length = translator->prefix_length;
    pthread_mutex_unlock(&translator->mutex);
    
    return true;
}

bool nat64_add_static_mapping(nat64_translator_t *translator, const ipv4_addr_t *ipv4_addr, 
                             const ipv6_addr_t *ipv6_addr) {
    if (!translator || !ipv4_addr || !ipv6_addr) {
        return false;
    }
    
    pthread_mutex_lock(&translator->mutex);
    
    nat64_mapping_t *mapping = nat64_create_mapping(translator, ipv4_addr, ipv6_addr, 0, 0, 0);
    if (mapping) {
        // Mark as static mapping (won't timeout)
        mapping->created_time_ns = 0;
        mapping->last_activity_ns = UINT64_MAX;
    }
    
    pthread_mutex_unlock(&translator->mutex);
    
    return (mapping != NULL);
}

bool nat64_remove_static_mapping(nat64_translator_t *translator, const ipv4_addr_t *ipv4_addr) {
    if (!translator || !ipv4_addr) {
        return false;
    }
    
    pthread_mutex_lock(&translator->mutex);
    
    bool found = false;
    for (size_t i = 0; i < translator->mapping_count; i++) {
        nat64_mapping_t *mapping = &translator->mappings[i];
        if (mapping->active && 
            mapping->ipv4_addr.addr == ipv4_addr->addr &&
            mapping->created_time_ns == 0) { // Static mapping marker
            mapping->active = false;
            translator->stats.active_mappings--;
            found = true;
            break;
        }
    }
    
    pthread_mutex_unlock(&translator->mutex);
    
    return found;
}

void nat64_set_mapping_timeout(nat64_translator_t *translator, uint32_t timeout_seconds) {
    if (!translator) {
        return;
    }
    
    pthread_mutex_lock(&translator->mutex);
    translator->mapping_timeout_seconds = timeout_seconds;
    pthread_mutex_unlock(&translator->mutex);
}

void nat64_cleanup_expired_mappings(nat64_translator_t *translator) {
    if (!translator) {
        return;
    }
    
    pthread_mutex_lock(&translator->mutex);
    
    uint64_t current_time = clock_gettime_nsec_np(CLOCK_MONOTONIC);
    uint64_t timeout_ns = (uint64_t)translator->mapping_timeout_seconds * 1000000000ULL;
    
    for (size_t i = 0; i < translator->mapping_count; i++) {
        nat64_mapping_t *mapping = &translator->mappings[i];
        if (mapping->active && 
            mapping->created_time_ns != 0 && // Not a static mapping
            (current_time - mapping->last_activity_ns) > timeout_ns) {
            mapping->active = false;
            translator->stats.active_mappings--;
            translator->stats.mapping_timeouts++;
        }
    }
    
    pthread_mutex_unlock(&translator->mutex);
}

size_t nat64_get_mapping_count(nat64_translator_t *translator) {
    if (!translator) {
        return 0;
    }
    
    pthread_mutex_lock(&translator->mutex);
    size_t active_count = 0;
    for (size_t i = 0; i < translator->mapping_count; i++) {
        if (translator->mappings[i].active) {
            active_count++;
        }
    }
    pthread_mutex_unlock(&translator->mutex);
    
    return active_count;
}