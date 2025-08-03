#ifndef RELATIVE_VPN_DNS_CACHE_H
#define RELATIVE_VPN_DNS_CACHE_H

#include "dns/resolver.h"
#include <stdint.h>
#include <stdbool.h>

typedef struct dns_cache dns_cache_t;

typedef struct dns_cache_entry {
    char hostname[DNS_MAX_NAME_LENGTH + 1];
    dns_record_type_t type;
    dns_record_t record;
    uint64_t expiry_time_ns;
    uint32_t access_count;
    uint64_t last_access_ns;
} dns_cache_entry_t;

typedef struct dns_cache_stats {
    uint32_t total_entries;
    uint32_t cache_hits;
    uint32_t cache_misses;
    uint32_t evictions;
    uint32_t expired_entries;
    uint64_t memory_usage;
} dns_cache_stats_t;

dns_cache_t *dns_cache_create(size_t max_entries, uint32_t default_ttl_seconds);
void dns_cache_destroy(dns_cache_t *cache);

bool dns_cache_put(dns_cache_t *cache, const char *hostname, dns_record_type_t type, 
                  const dns_record_t *record);
bool dns_cache_get(dns_cache_t *cache, const char *hostname, dns_record_type_t type, 
                  dns_record_t *record);

bool dns_cache_has_entry(dns_cache_t *cache, const char *hostname, dns_record_type_t type);
bool dns_cache_remove(dns_cache_t *cache, const char *hostname, dns_record_type_t type);
void dns_cache_clear(dns_cache_t *cache);

void dns_cache_cleanup_expired(dns_cache_t *cache);
void dns_cache_set_max_entries(dns_cache_t *cache, size_t max_entries);
void dns_cache_set_default_ttl(dns_cache_t *cache, uint32_t default_ttl_seconds);

size_t dns_cache_get_size(dns_cache_t *cache);
size_t dns_cache_get_max_size(dns_cache_t *cache);
void dns_cache_get_stats(dns_cache_t *cache, dns_cache_stats_t *stats);

bool dns_cache_export_entries(dns_cache_t *cache, dns_cache_entry_t *entries, size_t *count);
void dns_cache_print_stats(dns_cache_t *cache);

typedef enum cache_eviction_policy {
    DNS_CACHE_LRU = 0,
    DNS_CACHE_LFU = 1,
    DNS_CACHE_TTL = 2
} cache_eviction_policy_t;

void dns_cache_set_eviction_policy(dns_cache_t *cache, cache_eviction_policy_t policy);
bool dns_cache_evict_oldest(dns_cache_t *cache);

#endif