#include "mtu/discovery.h"
#include "core/logging.h"
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <netinet/icmp6.h>
#include <netinet/ip_icmp.h>
#include <arpa/inet.h>

#define MAX_MTU_PATHS 512
#define MTU_PROBE_INTERVAL_DEFAULT 300  // 5 minutes
#define MTU_STALE_TIMEOUT 3600         // 1 hour
#define MTU_PROBE_TIMEOUT 30           // 30 seconds

struct mtu_discovery {
    mtu_path_entry_t paths[MAX_MTU_PATHS];
    size_t path_count;
    uint16_t interface_mtu;
    bool pmtu_enabled;
    uint32_t probe_interval_seconds;
    uint64_t last_cleanup_ns;
    pthread_mutex_t mutex;
    mtu_update_callback_t update_callback;
    void *callback_user_data;
    mtu_stats_t stats;
};

static mtu_path_entry_t *mtu_find_path_entry(mtu_discovery_t *discovery, const ip_addr_t *destination);
static mtu_path_entry_t *mtu_create_path_entry(mtu_discovery_t *discovery, const ip_addr_t *destination);
static bool mtu_addr_equal(const ip_addr_t *addr1, const ip_addr_t *addr2, uint8_t ip_version);
static uint8_t mtu_get_ip_version(const ip_addr_t *addr);
static bool mtu_parse_tcp_options(const uint8_t *options, size_t options_len, uint16_t *mss);
static bool mtu_update_tcp_mss_option(uint8_t *options, size_t options_len, uint16_t new_mss);

mtu_discovery_t *mtu_discovery_create(uint16_t interface_mtu) {
    mtu_discovery_t *discovery = calloc(1, sizeof(mtu_discovery_t));
    if (!discovery) {
        LOG_ERROR("Failed to allocate MTU discovery");
        return NULL;
    }
    
    if (pthread_mutex_init(&discovery->mutex, NULL) != 0) {
        LOG_ERROR("Failed to initialize MTU discovery mutex");
        free(discovery);
        return NULL;
    }
    
    discovery->interface_mtu = interface_mtu ? interface_mtu : MTU_DEFAULT_IPV4;
    discovery->pmtu_enabled = true;
    discovery->probe_interval_seconds = MTU_PROBE_INTERVAL_DEFAULT;
    discovery->last_cleanup_ns = clock_gettime_nsec_np(CLOCK_MONOTONIC);
    
    LOG_INFO("MTU discovery created with interface MTU %d", discovery->interface_mtu);
    return discovery;
}

void mtu_discovery_destroy(mtu_discovery_t *discovery) {
    if (!discovery) return;
    
    pthread_mutex_lock(&discovery->mutex);
    
    for (size_t i = 0; i < discovery->path_count; i++) {
        discovery->paths[i].active = false;
    }
    discovery->path_count = 0;
    
    pthread_mutex_unlock(&discovery->mutex);
    pthread_mutex_destroy(&discovery->mutex);
    
    free(discovery);
    LOG_INFO("MTU discovery destroyed");
}

uint16_t mtu_discovery_get_path_mtu(mtu_discovery_t *discovery, const ip_addr_t *destination) {
    if (!discovery || !destination) return 0;
    
    pthread_mutex_lock(&discovery->mutex);
    
    mtu_path_entry_t *entry = mtu_find_path_entry(discovery, destination);
    uint16_t mtu = 0;
    
    if (entry && entry->active) {
        mtu = entry->current_mtu;
    } else {
        uint8_t ip_version = mtu_get_ip_version(destination);
        mtu = (ip_version == 6) ? MTU_DEFAULT_IPV6 : MTU_DEFAULT_IPV4;
        
        if (mtu > discovery->interface_mtu) {
            mtu = discovery->interface_mtu;
        }
    }
    
    pthread_mutex_unlock(&discovery->mutex);
    return mtu;
}

bool mtu_discovery_set_path_mtu(mtu_discovery_t *discovery, const ip_addr_t *destination, uint16_t mtu) {
    if (!discovery || !destination || mtu == 0) return false;
    
    pthread_mutex_lock(&discovery->mutex);
    
    mtu_path_entry_t *entry = mtu_find_path_entry(discovery, destination);
    if (!entry) {
        entry = mtu_create_path_entry(discovery, destination);
        if (!entry) {
            pthread_mutex_unlock(&discovery->mutex);
            return false;
        }
    }
    
    uint16_t old_mtu = entry->current_mtu;
    entry->current_mtu = mtu;
    entry->discovered_mtu = mtu;
    entry->last_updated_ns = clock_gettime_nsec_np(CLOCK_MONOTONIC);
    
    if (old_mtu != mtu && discovery->update_callback) {
        discovery->update_callback(destination, old_mtu, mtu, discovery->callback_user_data);
    }
    
    if (mtu < old_mtu) {
        discovery->stats.mtu_reductions++;
    }
    
    pthread_mutex_unlock(&discovery->mutex);
    
    LOG_DEBUG("Updated path MTU for destination to %d", mtu);
    return true;
}

bool mtu_discovery_start_probe(mtu_discovery_t *discovery, const ip_addr_t *destination) {
    if (!discovery || !destination || !discovery->pmtu_enabled) return false;
    
    pthread_mutex_lock(&discovery->mutex);
    
    mtu_path_entry_t *entry = mtu_find_path_entry(discovery, destination);
    if (!entry) {
        entry = mtu_create_path_entry(discovery, destination);
        if (!entry) {
            pthread_mutex_unlock(&discovery->mutex);
            return false;
        }
    }
    
    uint64_t current_time = clock_gettime_nsec_np(CLOCK_MONOTONIC);
    uint64_t probe_interval_ns = discovery->probe_interval_seconds * 1000000000ULL;
    
    if (current_time - entry->last_probe_ns < probe_interval_ns) {
        pthread_mutex_unlock(&discovery->mutex);
        return false;
    }
    
    entry->last_probe_ns = current_time;
    entry->probe_count++;
    discovery->stats.probes_sent++;
    
    pthread_mutex_unlock(&discovery->mutex);
    
    LOG_DEBUG("Started MTU probe for destination");
    return true;
}

void mtu_discovery_process_icmp_error(mtu_discovery_t *discovery, const uint8_t *packet, size_t length, 
                                     const ip_addr_t *src_addr) {
    if (!discovery || !packet || length == 0 || !src_addr) return;
    
    pthread_mutex_lock(&discovery->mutex);
    
    ip_addr_t original_dest;
    uint16_t suggested_mtu;
    
    if (mtu_is_fragmentation_needed(packet, length, &original_dest, &suggested_mtu)) {
        mtu_path_entry_t *entry = mtu_find_path_entry(discovery, &original_dest);
        if (entry && entry->active) {
            uint8_t ip_version = entry->ip_version;
            uint16_t min_mtu = (ip_version == 6) ? MTU_MIN_IPV6 : MTU_MIN_IPV4;
            
            if (suggested_mtu >= min_mtu && suggested_mtu < entry->current_mtu) {
                uint16_t old_mtu = entry->current_mtu;
                entry->current_mtu = suggested_mtu;
                entry->discovered_mtu = suggested_mtu;
                entry->last_updated_ns = clock_gettime_nsec_np(CLOCK_MONOTONIC);
                
                discovery->stats.responses_received++;
                discovery->stats.mtu_reductions++;
                
                if (discovery->update_callback) {
                    discovery->update_callback(&original_dest, old_mtu, suggested_mtu, 
                                             discovery->callback_user_data);
                }
                
                LOG_INFO("Reduced path MTU for destination from %d to %d", old_mtu, suggested_mtu);
            }
        }
    }
    
    pthread_mutex_unlock(&discovery->mutex);
}

bool mtu_clamp_tcp_mss(mtu_discovery_t *discovery, uint8_t *packet, size_t packet_length, 
                      const ip_addr_t *destination) {
    if (!discovery || !packet || packet_length == 0 || !destination) return false;
    
    uint8_t ip_version = (packet[0] >> 4) & 0x0F;
    
    if (ip_version == 4 && packet_length >= sizeof(struct ip)) {
        struct ip *ip_hdr = (struct ip *)packet;
        
        if (ip_hdr->ip_p == IPPROTO_TCP && 
            packet_length >= (ip_hdr->ip_hl * 4) + sizeof(struct tcphdr)) {
            
            struct tcphdr *tcp_hdr = (struct tcphdr *)(packet + (ip_hdr->ip_hl * 4));
            
            if (tcp_hdr->th_flags & TH_SYN) {
                uint16_t path_mtu = mtu_discovery_get_path_mtu(discovery, destination);
                uint16_t max_mss = mtu_calculate_tcp_mss_ipv4(path_mtu);
                
                size_t tcp_header_len = tcp_hdr->th_off * 4;
                if (tcp_header_len > sizeof(struct tcphdr)) {
                    uint8_t *options = (uint8_t *)tcp_hdr + sizeof(struct tcphdr);
                    size_t options_len = tcp_header_len - sizeof(struct tcphdr);
                    
                    uint16_t current_mss;
                    if (mtu_parse_tcp_options(options, options_len, &current_mss)) {
                        if (current_mss > max_mss) {
                            if (mtu_update_tcp_mss_option(options, options_len, max_mss)) {
                                tcp_hdr->th_sum = 0;
                                
                                discovery->stats.packets_clamped++;
                                discovery->stats.total_bytes_clamped += packet_length;
                                
                                LOG_DEBUG("Clamped TCP MSS from %d to %d", current_mss, max_mss);
                                return true;
                            }
                        }
                    }
                }
            }
        }
    } else if (ip_version == 6 && packet_length >= sizeof(struct ip6_hdr)) {
        struct ip6_hdr *ip6_hdr = (struct ip6_hdr *)packet;
        
        if (ip6_hdr->ip6_nxt == IPPROTO_TCP && 
            packet_length >= sizeof(struct ip6_hdr) + sizeof(struct tcphdr)) {
            
            struct tcphdr *tcp_hdr = (struct tcphdr *)(packet + sizeof(struct ip6_hdr));
            
            if (tcp_hdr->th_flags & TH_SYN) {
                uint16_t path_mtu = mtu_discovery_get_path_mtu(discovery, destination);
                uint16_t max_mss = mtu_calculate_tcp_mss_ipv6(path_mtu);
                
                size_t tcp_header_len = tcp_hdr->th_off * 4;
                if (tcp_header_len > sizeof(struct tcphdr)) {
                    uint8_t *options = (uint8_t *)tcp_hdr + sizeof(struct tcphdr);
                    size_t options_len = tcp_header_len - sizeof(struct tcphdr);
                    
                    uint16_t current_mss;
                    if (mtu_parse_tcp_options(options, options_len, &current_mss)) {
                        if (current_mss > max_mss) {
                            if (mtu_update_tcp_mss_option(options, options_len, max_mss)) {
                                tcp_hdr->th_sum = 0;
                                
                                discovery->stats.packets_clamped++;
                                discovery->stats.total_bytes_clamped += packet_length;
                                
                                LOG_DEBUG("Clamped TCP MSS from %d to %d", current_mss, max_mss);
                                return true;
                            }
                        }
                    }
                }
            }
        }
    }
    
    return false;
}

bool mtu_validate_packet_size(mtu_discovery_t *discovery, const uint8_t *packet, size_t length, 
                             const ip_addr_t *destination) {
    if (!discovery || !packet || length == 0 || !destination) return false;
    
    uint16_t path_mtu = mtu_discovery_get_path_mtu(discovery, destination);
    
    return length <= path_mtu;
}

void mtu_discovery_cleanup_stale_entries(mtu_discovery_t *discovery) {
    if (!discovery) return;
    
    pthread_mutex_lock(&discovery->mutex);
    
    uint64_t current_time = clock_gettime_nsec_np(CLOCK_MONOTONIC);
    uint64_t stale_timeout_ns = MTU_STALE_TIMEOUT * 1000000000ULL;
    
    size_t removed_count = 0;
    
    for (size_t i = 0; i < discovery->path_count; i++) {
        mtu_path_entry_t *entry = &discovery->paths[i];
        
        if (entry->active && (current_time - entry->last_updated_ns) > stale_timeout_ns) {
            entry->active = false;
            removed_count++;
        }
    }
    
    if (removed_count > 0) {
        size_t write_index = 0;
        for (size_t read_index = 0; read_index < discovery->path_count; read_index++) {
            if (discovery->paths[read_index].active) {
                if (write_index != read_index) {
                    discovery->paths[write_index] = discovery->paths[read_index];
                }
                write_index++;
            }
        }
        discovery->path_count = write_index;
        
        LOG_DEBUG("Cleaned up %zu stale MTU path entries", removed_count);
    }
    
    discovery->last_cleanup_ns = current_time;
    
    pthread_mutex_unlock(&discovery->mutex);
}

static mtu_path_entry_t *mtu_find_path_entry(mtu_discovery_t *discovery, const ip_addr_t *destination) {
    uint8_t ip_version = mtu_get_ip_version(destination);
    
    for (size_t i = 0; i < discovery->path_count; i++) {
        mtu_path_entry_t *entry = &discovery->paths[i];
        if (entry->active && 
            entry->ip_version == ip_version &&
            mtu_addr_equal(&entry->destination, destination, ip_version)) {
            return entry;
        }
    }
    
    return NULL;
}

static mtu_path_entry_t *mtu_create_path_entry(mtu_discovery_t *discovery, const ip_addr_t *destination) {
    if (discovery->path_count >= MAX_MTU_PATHS) {
        LOG_WARN("MTU path table full");
        return NULL;
    }
    
    mtu_path_entry_t *entry = &discovery->paths[discovery->path_count++];
    memset(entry, 0, sizeof(mtu_path_entry_t));
    
    entry->destination = *destination;
    entry->ip_version = mtu_get_ip_version(destination);
    entry->current_mtu = (entry->ip_version == 6) ? MTU_DEFAULT_IPV6 : MTU_DEFAULT_IPV4;
    entry->discovered_mtu = entry->current_mtu;
    entry->last_updated_ns = clock_gettime_nsec_np(CLOCK_MONOTONIC);
    entry->pmtu_enabled = discovery->pmtu_enabled;
    entry->active = true;
    
    if (entry->current_mtu > discovery->interface_mtu) {
        entry->current_mtu = discovery->interface_mtu;
        entry->discovered_mtu = discovery->interface_mtu;
    }
    
    discovery->stats.total_paths++;
    discovery->stats.active_paths++;
    
    return entry;
}

static bool mtu_addr_equal(const ip_addr_t *addr1, const ip_addr_t *addr2, uint8_t ip_version) {
    if (ip_version == 4) {
        return addr1->v4.addr == addr2->v4.addr;
    } else {
        return memcmp(addr1->v6.addr, addr2->v6.addr, 16) == 0;
    }
}

static uint8_t mtu_get_ip_version(const ip_addr_t *addr) {
    return (addr->v4.addr != 0) ? 4 : 6;
}

static bool mtu_parse_tcp_options(const uint8_t *options, size_t options_len, uint16_t *mss) {
    size_t offset = 0;
    
    while (offset < options_len) {
        uint8_t option_type = options[offset];
        
        if (option_type == 0) break;        // End of options
        if (option_type == 1) {             // NOP
            offset++;
            continue;
        }
        
        if (offset + 1 >= options_len) break;
        uint8_t option_len = options[offset + 1];
        
        if (option_len < 2 || offset + option_len > options_len) break;
        
        if (option_type == 2 && option_len == 4) { // MSS option
            *mss = ntohs(*(uint16_t*)(options + offset + 2));
            return true;
        }
        
        offset += option_len;
    }
    
    return false;
}

static bool mtu_update_tcp_mss_option(uint8_t *options, size_t options_len, uint16_t new_mss) {
    size_t offset = 0;
    
    while (offset < options_len) {
        uint8_t option_type = options[offset];
        
        if (option_type == 0) break;
        if (option_type == 1) {
            offset++;
            continue;
        }
        
        if (offset + 1 >= options_len) break;
        uint8_t option_len = options[offset + 1];
        
        if (option_len < 2 || offset + option_len > options_len) break;
        
        if (option_type == 2 && option_len == 4) {
            *(uint16_t*)(options + offset + 2) = htons(new_mss);
            return true;
        }
        
        offset += option_len;
    }
    
    return false;
}

uint16_t mtu_calculate_tcp_mss_ipv4(uint16_t mtu) {
    uint16_t mss = mtu - sizeof(struct ip) - sizeof(struct tcphdr);
    return mss < MSS_MIN_IPV4 ? MSS_MIN_IPV4 : mss;
}

uint16_t mtu_calculate_tcp_mss_ipv6(uint16_t mtu) {
    uint16_t mss = mtu - sizeof(struct ip6_hdr) - sizeof(struct tcphdr);
    return mss < MSS_MIN_IPV6 ? MSS_MIN_IPV6 : mss;
}

uint16_t mtu_get_recommended_mtu(uint8_t ip_version) {
    return (ip_version == 6) ? MTU_DEFAULT_IPV6 : MTU_DEFAULT_IPV4;
}

bool mtu_is_fragmentation_needed(const uint8_t *icmp_packet, size_t length, 
                                ip_addr_t *original_dest, uint16_t *suggested_mtu) {
    if (!icmp_packet || length < sizeof(struct icmp) || !original_dest || !suggested_mtu) {
        return false;
    }
    
    const struct icmp *icmp_hdr = (const struct icmp *)icmp_packet;
    
    if (icmp_hdr->icmp_type == ICMP_UNREACH && icmp_hdr->icmp_code == ICMP_UNREACH_NEEDFRAG) {
        if (length >= sizeof(struct icmp) + sizeof(struct ip)) {
            const struct ip *orig_ip = (const struct ip *)(icmp_packet + sizeof(struct icmp));
            original_dest->v4.addr = orig_ip->ip_dst.s_addr;
            *suggested_mtu = ntohs(icmp_hdr->icmp_nextmtu);
            return true;
        }
    }
    
    return false;
}