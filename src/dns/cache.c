#include "dns/cache.h"
#include "core/logging.h"
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <time.h>

#if defined(TARGET_OS_IOS) || defined(__APPLE__)
#include <CommonCrypto/CommonHMAC.h>
#include <Security/SecRandom.h>
#else
#include <openssl/hmac.h>
#include <openssl/rand.h>
#endif

#define DNS_CACHE_DEFAULT_TTL 300 // 5 minutes

struct dns_cache_bucket {
    dns_cache_entry_t *entry;
    struct dns_cache_bucket *next;
};

struct dns_cache {
    struct dns_cache_bucket **buckets;
    size_t bucket_count;
    size_t max_entries;
    size_t current_entries;
    uint32_t default_ttl_seconds;
    // SECURITY FIX: Cryptographically secure hash key for collision resistance
    uint8_t hash_key[32]; // 256-bit key for HMAC-SHA256
    cache_eviction_policy_t eviction_policy;
    pthread_mutex_t mutex;
    
    dns_cache_stats_t stats;
};

static uint32_t dns_cache_hash(dns_cache_t *cache, const char *hostname, dns_record_type_t type);
static void dns_cache_evict_lru(dns_cache_t *cache);
static void dns_cache_evict_lfu(dns_cache_t *cache);
static void dns_cache_evict_expired(dns_cache_t *cache);
static bool dns_cache_is_expired(const dns_cache_entry_t *entry);

dns_cache_t *dns_cache_create(size_t max_entries, uint32_t default_ttl_seconds) {
    if (max_entries == 0) {
        LOG_ERROR("DNS cache max_entries cannot be zero");
        return NULL;
    }
    
    dns_cache_t *cache = calloc(1, sizeof(dns_cache_t));
    if (!cache) {
        LOG_ERROR("Failed to allocate DNS cache");
        return NULL;
    }
    
    cache->bucket_count = max_entries * 2; // Load factor of 0.5
    cache->buckets = calloc(cache->bucket_count, sizeof(struct dns_cache_bucket*));
    if (!cache->buckets) {
        LOG_ERROR("Failed to allocate DNS cache buckets");
        free(cache);
        return NULL;
    }
    
    if (pthread_mutex_init(&cache->mutex, NULL) != 0) {
        LOG_ERROR("Failed to initialize DNS cache mutex");
        free(cache->buckets);
        free(cache);
        return NULL;
    }
    
    cache->max_entries = max_entries;
    cache->default_ttl_seconds = default_ttl_seconds ? default_ttl_seconds : DNS_CACHE_DEFAULT_TTL;
    cache->eviction_policy = DNS_CACHE_LRU;
    
    // SECURITY FIX: Generate cryptographically secure random key for hash function
#ifdef TARGET_OS_IOS
    if (SecRandomCopyBytes(kSecRandomDefault, sizeof(cache->hash_key), cache->hash_key) != errSecSuccess) {
        LOG_ERROR("Failed to generate secure random key for DNS cache");
        pthread_mutex_destroy(&cache->mutex);
        free(cache->buckets);
        free(cache);
        return NULL;
    }
#else
    if (RAND_bytes(cache->hash_key, sizeof(cache->hash_key)) != 1) {
        LOG_ERROR("Failed to generate secure random key for DNS cache");
        pthread_mutex_destroy(&cache->mutex);
        free(cache->buckets);
        free(cache);
        return NULL;
    }
#endif
    
    LOG_INFO("DNS cache created with %zu max entries", max_entries);
    return cache;
}

void dns_cache_destroy(dns_cache_t *cache) {
    if (!cache) return;
    
    pthread_mutex_lock(&cache->mutex);
    
    for (size_t i = 0; i < cache->bucket_count; i++) {
        struct dns_cache_bucket *bucket = cache->buckets[i];
        while (bucket) {
            struct dns_cache_bucket *next = bucket->next;
            free(bucket->entry);
            free(bucket);
            bucket = next;
        }
    }
    
    free(cache->buckets);
    
    pthread_mutex_unlock(&cache->mutex);
    pthread_mutex_destroy(&cache->mutex);
    
    free(cache);
    LOG_INFO("DNS cache destroyed");
}

bool dns_cache_put(dns_cache_t *cache, const char *hostname, dns_record_type_t type, 
                  const dns_record_t *record) {
    if (!cache || !hostname || !record) return false;
    
    pthread_mutex_lock(&cache->mutex);
    
    if (cache->current_entries >= cache->max_entries) {
        switch (cache->eviction_policy) {
            case DNS_CACHE_LRU:
                dns_cache_evict_lru(cache);
                break;
            case DNS_CACHE_LFU:
                dns_cache_evict_lfu(cache);
                break;
            case DNS_CACHE_TTL:
                dns_cache_evict_expired(cache);
                break;
        }
        
        if (cache->current_entries >= cache->max_entries) {
            LOG_WARN("DNS cache is full, cannot add entry for %s", hostname);
            pthread_mutex_unlock(&cache->mutex);
            return false;
        }
    }
    
    uint32_t hash = dns_cache_hash(cache, hostname, type);
    size_t bucket_index = hash % cache->bucket_count;
    
    struct dns_cache_bucket *bucket = cache->buckets[bucket_index];
    while (bucket) {
        if (bucket->entry && 
            strcmp(bucket->entry->hostname, hostname) == 0 && 
            bucket->entry->type == type) {
            
            bucket->entry->record = *record;
            bucket->entry->expiry_time_ns = clock_gettime_nsec_np(CLOCK_MONOTONIC) + 
                                           (record->ttl > 0 ? record->ttl : cache->default_ttl_seconds) * 1000000000ULL;
            bucket->entry->last_access_ns = bucket->entry->expiry_time_ns;
            bucket->entry->access_count++;
            
            LOG_DEBUG("Updated DNS cache entry for %s (type %d)", hostname, type);
            pthread_mutex_unlock(&cache->mutex);
            return true;
        }
        bucket = bucket->next;
    }
    
    struct dns_cache_bucket *new_bucket = calloc(1, sizeof(struct dns_cache_bucket));
    if (!new_bucket) {
        LOG_ERROR("Failed to allocate DNS cache bucket");
        pthread_mutex_unlock(&cache->mutex);
        return false;
    }
    
    new_bucket->entry = calloc(1, sizeof(dns_cache_entry_t));
    if (!new_bucket->entry) {
        LOG_ERROR("Failed to allocate DNS cache entry");
        free(new_bucket);
        pthread_mutex_unlock(&cache->mutex);
        return false;
    }
    
    strncpy(new_bucket->entry->hostname, hostname, DNS_MAX_NAME_LENGTH);
    new_bucket->entry->type = type;
    new_bucket->entry->record = *record;
    new_bucket->entry->expiry_time_ns = clock_gettime_nsec_np(CLOCK_MONOTONIC) + 
                                       (record->ttl > 0 ? record->ttl : cache->default_ttl_seconds) * 1000000000ULL;
    new_bucket->entry->last_access_ns = new_bucket->entry->expiry_time_ns;
    new_bucket->entry->access_count = 1;
    
    new_bucket->next = cache->buckets[bucket_index];
    cache->buckets[bucket_index] = new_bucket;
    cache->current_entries++;
    
    cache->stats.memory_usage += sizeof(dns_cache_entry_t) + sizeof(struct dns_cache_bucket);
    
    LOG_DEBUG("Added DNS cache entry for %s (type %d)", hostname, type);
    
    pthread_mutex_unlock(&cache->mutex);
    return true;
}

bool dns_cache_get(dns_cache_t *cache, const char *hostname, dns_record_type_t type, 
                  dns_record_t *record) {
    if (!cache || !hostname || !record) return false;
    
    pthread_mutex_lock(&cache->mutex);
    
    uint32_t hash = dns_cache_hash(cache, hostname, type);
    size_t bucket_index = hash % cache->bucket_count;
    
    struct dns_cache_bucket *bucket = cache->buckets[bucket_index];
    while (bucket) {
        if (bucket->entry && 
            strcmp(bucket->entry->hostname, hostname) == 0 && 
            bucket->entry->type == type) {
            
            if (dns_cache_is_expired(bucket->entry)) {
                LOG_DEBUG("DNS cache entry for %s expired", hostname);
                cache->stats.cache_misses++;
                cache->stats.expired_entries++;
                pthread_mutex_unlock(&cache->mutex);
                return false;
            }
            
            *record = bucket->entry->record;
            bucket->entry->last_access_ns = clock_gettime_nsec_np(CLOCK_MONOTONIC);
            bucket->entry->access_count++;
            
            cache->stats.cache_hits++;
            
            LOG_DEBUG("DNS cache hit for %s (type %d)", hostname, type);
            pthread_mutex_unlock(&cache->mutex);
            return true;
        }
        bucket = bucket->next;
    }
    
    cache->stats.cache_misses++;
    
    LOG_DEBUG("DNS cache miss for %s (type %d)", hostname, type);
    pthread_mutex_unlock(&cache->mutex);
    return false;
}

bool dns_cache_has_entry(dns_cache_t *cache, const char *hostname, dns_record_type_t type) {
    if (!cache || !hostname) return false;
    
    pthread_mutex_lock(&cache->mutex);
    
    uint32_t hash = dns_cache_hash(cache, hostname, type);
    size_t bucket_index = hash % cache->bucket_count;
    
    struct dns_cache_bucket *bucket = cache->buckets[bucket_index];
    while (bucket) {
        if (bucket->entry && 
            strcmp(bucket->entry->hostname, hostname) == 0 && 
            bucket->entry->type == type) {
            
            bool has_entry = !dns_cache_is_expired(bucket->entry);
            pthread_mutex_unlock(&cache->mutex);
            return has_entry;
        }
        bucket = bucket->next;
    }
    
    pthread_mutex_unlock(&cache->mutex);
    return false;
}

bool dns_cache_remove(dns_cache_t *cache, const char *hostname, dns_record_type_t type) {
    if (!cache || !hostname) return false;
    
    pthread_mutex_lock(&cache->mutex);
    
    uint32_t hash = dns_cache_hash(cache, hostname, type);
    size_t bucket_index = hash % cache->bucket_count;
    
    struct dns_cache_bucket **bucket_ptr = &cache->buckets[bucket_index];
    while (*bucket_ptr) {
        struct dns_cache_bucket *bucket = *bucket_ptr;
        if (bucket->entry && 
            strcmp(bucket->entry->hostname, hostname) == 0 && 
            bucket->entry->type == type) {
            
            *bucket_ptr = bucket->next;
            free(bucket->entry);
            free(bucket);
            cache->current_entries--;
            cache->stats.memory_usage -= sizeof(dns_cache_entry_t) + sizeof(struct dns_cache_bucket);
            
            LOG_DEBUG("Removed DNS cache entry for %s (type %d)", hostname, type);
            pthread_mutex_unlock(&cache->mutex);
            return true;
        }
        bucket_ptr = &bucket->next;
    }
    
    pthread_mutex_unlock(&cache->mutex);
    return false;
}

void dns_cache_clear(dns_cache_t *cache) {
    if (!cache) return;
    
    pthread_mutex_lock(&cache->mutex);
    
    for (size_t i = 0; i < cache->bucket_count; i++) {
        struct dns_cache_bucket *bucket = cache->buckets[i];
        while (bucket) {
            struct dns_cache_bucket *next = bucket->next;
            free(bucket->entry);
            free(bucket);
            bucket = next;
        }
        cache->buckets[i] = NULL;
    }
    
    cache->current_entries = 0;
    cache->stats.memory_usage = 0;
    
    LOG_INFO("DNS cache cleared");
    pthread_mutex_unlock(&cache->mutex);
}

void dns_cache_cleanup_expired(dns_cache_t *cache) {
    if (!cache) return;
    
    pthread_mutex_lock(&cache->mutex);
    
    size_t removed_count = 0;
    
    for (size_t i = 0; i < cache->bucket_count; i++) {
        struct dns_cache_bucket **bucket_ptr = &cache->buckets[i];
        while (*bucket_ptr) {
            struct dns_cache_bucket *bucket = *bucket_ptr;
            if (bucket->entry && dns_cache_is_expired(bucket->entry)) {
                *bucket_ptr = bucket->next;
                free(bucket->entry);
                free(bucket);
                cache->current_entries--;
                cache->stats.memory_usage -= sizeof(dns_cache_entry_t) + sizeof(struct dns_cache_bucket);
                cache->stats.expired_entries++;
                removed_count++;
            } else {
                bucket_ptr = &bucket->next;
            }
        }
    }
    
    if (removed_count > 0) {
        LOG_DEBUG("Cleaned up %zu expired DNS cache entries", removed_count);
    }
    
    pthread_mutex_unlock(&cache->mutex);
}

size_t dns_cache_get_size(dns_cache_t *cache) {
    if (!cache) return 0;
    
    pthread_mutex_lock(&cache->mutex);
    size_t size = cache->current_entries;
    pthread_mutex_unlock(&cache->mutex);
    
    return size;
}

size_t dns_cache_get_max_size(dns_cache_t *cache) {
    return cache ? cache->max_entries : 0;
}

void dns_cache_get_stats(dns_cache_t *cache, dns_cache_stats_t *stats) {
    if (!cache || !stats) return;
    
    pthread_mutex_lock(&cache->mutex);
    cache->stats.total_entries = cache->current_entries;
    *stats = cache->stats;
    pthread_mutex_unlock(&cache->mutex);
}

// SECURITY FIX: Cryptographically secure hash function using HMAC-SHA256
static uint32_t dns_cache_hash(dns_cache_t *cache, const char *hostname, dns_record_type_t type) {
    if (!cache || !hostname) return 0;
    
    // Create input data combining hostname and type
    size_t hostname_len = strlen(hostname);
    size_t input_len = hostname_len + sizeof(dns_record_type_t);
    uint8_t *input_data = malloc(input_len);
    if (!input_data) {
        LOG_ERROR("Failed to allocate memory for DNS cache hash input");
        return 0;
    }
    
    memcpy(input_data, hostname, hostname_len);
    memcpy(input_data + hostname_len, &type, sizeof(dns_record_type_t));
    
    uint8_t hmac_output[32]; // SHA-256 output is 32 bytes
    
#ifdef TARGET_OS_IOS
    // Use iOS CommonCrypto
    CCHmac(kCCHmacAlgSHA256, cache->hash_key, sizeof(cache->hash_key),
           input_data, input_len, hmac_output);
#else
    // Use OpenSSL
    unsigned int hmac_len;
    HMAC(EVP_sha256(), cache->hash_key, sizeof(cache->hash_key),
         input_data, input_len, hmac_output, &hmac_len);
#endif
    
    free(input_data);
    
    // Convert first 4 bytes of HMAC output to uint32_t for bucket selection
    uint32_t hash = 0;
    hash = (hash << 8) | hmac_output[0];
    hash = (hash << 8) | hmac_output[1];
    hash = (hash << 8) | hmac_output[2];
    hash = (hash << 8) | hmac_output[3];
    
    return hash;
}

static bool dns_cache_is_expired(const dns_cache_entry_t *entry) {
    if (!entry) return true;
    
    uint64_t current_time = clock_gettime_nsec_np(CLOCK_MONOTONIC);
    return current_time > entry->expiry_time_ns;
}

static void dns_cache_evict_lru(dns_cache_t *cache) {
    if (!cache || cache->current_entries == 0) return;
    
    uint64_t oldest_access = UINT64_MAX;
    struct dns_cache_bucket **oldest_bucket_ptr = NULL;
    size_t oldest_bucket_index = 0;
    
    for (size_t i = 0; i < cache->bucket_count; i++) {
        struct dns_cache_bucket **bucket_ptr = &cache->buckets[i];
        while (*bucket_ptr) {
            struct dns_cache_bucket *bucket = *bucket_ptr;
            if (bucket->entry && bucket->entry->last_access_ns < oldest_access) {
                oldest_access = bucket->entry->last_access_ns;
                oldest_bucket_ptr = bucket_ptr;
                oldest_bucket_index = i;
            }
            bucket_ptr = &bucket->next;
        }
    }
    
    if (oldest_bucket_ptr) {
        struct dns_cache_bucket *bucket = *oldest_bucket_ptr;
        *oldest_bucket_ptr = bucket->next;
        
        LOG_DEBUG("Evicted LRU DNS cache entry for %s", bucket->entry->hostname);
        
        free(bucket->entry);
        free(bucket);
        cache->current_entries--;
        cache->stats.memory_usage -= sizeof(dns_cache_entry_t) + sizeof(struct dns_cache_bucket);
        cache->stats.evictions++;
    }
}

static void dns_cache_evict_lfu(dns_cache_t *cache) {
    if (!cache || cache->current_entries == 0) return;
    
    uint32_t lowest_count = UINT32_MAX;
    struct dns_cache_bucket **lowest_bucket_ptr = NULL;
    
    for (size_t i = 0; i < cache->bucket_count; i++) {
        struct dns_cache_bucket **bucket_ptr = &cache->buckets[i];
        while (*bucket_ptr) {
            struct dns_cache_bucket *bucket = *bucket_ptr;
            if (bucket->entry && bucket->entry->access_count < lowest_count) {
                lowest_count = bucket->entry->access_count;
                lowest_bucket_ptr = bucket_ptr;
            }
            bucket_ptr = &bucket->next;
        }
    }
    
    if (lowest_bucket_ptr) {
        struct dns_cache_bucket *bucket = *lowest_bucket_ptr;
        *lowest_bucket_ptr = bucket->next;
        
        LOG_DEBUG("Evicted LFU DNS cache entry for %s", bucket->entry->hostname);
        
        free(bucket->entry);
        free(bucket);
        cache->current_entries--;
        cache->stats.memory_usage -= sizeof(dns_cache_entry_t) + sizeof(struct dns_cache_bucket);
        cache->stats.evictions++;
    }
}

static void dns_cache_evict_expired(dns_cache_t *cache) {
    dns_cache_cleanup_expired(cache);
}

// PRODUCTION FIX: Add missing DNS cache eviction policy function  
void dns_cache_set_eviction_policy(dns_cache_t *cache, cache_eviction_policy_t policy) {
    if (!cache) {
        return;
    }
    
    pthread_mutex_lock(&cache->mutex);
    cache->eviction_policy = policy;
    pthread_mutex_unlock(&cache->mutex);
    
    LOG_DEBUG("DNS cache eviction policy set to %d", policy);
}

// Additional function for vpn_engine.c compatibility
bool dns_cache_evict_oldest(dns_cache_t *cache) {
    if (!cache) {
        return false;
    }
    
    // Use LRU eviction to evict the oldest entry
    dns_cache_evict_lru(cache);
    return true;
}