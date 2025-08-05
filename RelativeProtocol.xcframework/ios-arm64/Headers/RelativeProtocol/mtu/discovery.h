#ifndef RELATIVE_VPN_MTU_DISCOVERY_H
#define RELATIVE_VPN_MTU_DISCOVERY_H

#include "core/types.h"
#include <stdint.h>
#include <stdbool.h>

#define MTU_MIN_IPV4 576
#define MTU_MIN_IPV6 1280
#define MTU_MAX_ETHERNET 1500
#define MTU_MAX_JUMBO 9000
#define MTU_DEFAULT_IPV4 1500
#define MTU_DEFAULT_IPV6 1500

#define MSS_MIN_IPV4 536   // MTU_MIN_IPV4 - IP_HEADER - TCP_HEADER
#define MSS_MIN_IPV6 1220  // MTU_MIN_IPV6 - IP6_HEADER - TCP_HEADER
#define MSS_DEFAULT_IPV4 1460
#define MSS_DEFAULT_IPV6 1440

typedef struct mtu_discovery mtu_discovery_t;

typedef struct mtu_path_entry {
    ip_addr_t destination;
    uint8_t ip_version;
    uint16_t discovered_mtu;
    uint16_t current_mtu;
    uint64_t last_updated_ns;
    uint64_t last_probe_ns;
    uint32_t probe_count;
    uint32_t timeout_count;
    bool pmtu_enabled;
    bool active;
} mtu_path_entry_t;

typedef struct mtu_stats {
    uint32_t total_paths;
    uint32_t active_paths;
    uint32_t probes_sent;
    uint32_t responses_received;
    uint32_t timeouts;
    uint32_t mtu_reductions;
    uint32_t packets_clamped;
    uint64_t total_bytes_clamped;
} mtu_stats_t;

typedef void (*mtu_update_callback_t)(const ip_addr_t *destination, uint16_t old_mtu, uint16_t new_mtu, void *user_data);

mtu_discovery_t *mtu_discovery_create(uint16_t interface_mtu);
void mtu_discovery_destroy(mtu_discovery_t *discovery);

uint16_t mtu_discovery_get_path_mtu(mtu_discovery_t *discovery, const ip_addr_t *destination);
bool mtu_discovery_set_path_mtu(mtu_discovery_t *discovery, const ip_addr_t *destination, uint16_t mtu);

bool mtu_discovery_start_probe(mtu_discovery_t *discovery, const ip_addr_t *destination);
void mtu_discovery_process_icmp_error(mtu_discovery_t *discovery, const uint8_t *packet, size_t length, 
                                     const ip_addr_t *src_addr);

bool mtu_clamp_tcp_mss(mtu_discovery_t *discovery, uint8_t *packet, size_t packet_length, 
                      const ip_addr_t *destination);
bool mtu_validate_packet_size(mtu_discovery_t *discovery, const uint8_t *packet, size_t length, 
                             const ip_addr_t *destination);

void mtu_discovery_set_interface_mtu(mtu_discovery_t *discovery, uint16_t mtu);
uint16_t mtu_discovery_get_interface_mtu(mtu_discovery_t *discovery);

void mtu_discovery_enable_pmtu(mtu_discovery_t *discovery, bool enable);
bool mtu_discovery_is_pmtu_enabled(mtu_discovery_t *discovery);

void mtu_discovery_set_probe_interval(mtu_discovery_t *discovery, uint32_t interval_seconds);
void mtu_discovery_set_update_callback(mtu_discovery_t *discovery, mtu_update_callback_t callback, void *user_data);

void mtu_discovery_cleanup_stale_entries(mtu_discovery_t *discovery);
size_t mtu_discovery_get_path_count(mtu_discovery_t *discovery);
bool mtu_discovery_get_path_entry(mtu_discovery_t *discovery, size_t index, mtu_path_entry_t *entry);
void mtu_discovery_get_stats(mtu_discovery_t *discovery, mtu_stats_t *stats);

uint16_t mtu_calculate_tcp_mss_ipv4(uint16_t mtu);
uint16_t mtu_calculate_tcp_mss_ipv6(uint16_t mtu);
uint16_t mtu_get_recommended_mtu(uint8_t ip_version);

bool mtu_is_fragmentation_needed(const uint8_t *icmp_packet, size_t length, 
                                ip_addr_t *original_dest, uint16_t *suggested_mtu);

void mtu_print_path_table(mtu_discovery_t *discovery);
void mtu_print_stats(const mtu_stats_t *stats);

#endif