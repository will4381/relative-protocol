#include "privacy/guards.h"
#include "core/logging.h"
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <CommonCrypto/CommonDigest.h>

#define MAX_ALLOWED_DNS_SERVERS 8
#define MAX_RECENT_VIOLATIONS 100
#define DNS_PORT 53
#define DNS_TLS_PORT 853
#define HTTPS_PORT 443
#define WEBRTC_STUN_PORT_START 3478
#define WEBRTC_STUN_PORT_END 3479
#define MAX_PINNED_CERTS 32
#define SHA256_DIGEST_LENGTH 32
#define MAX_CERTIFICATE_SIZE (64 * 1024)  // 64KB max certificate size

// Known DoH provider IP addresses (major ones)
static const uint32_t KNOWN_DOH_IPV4[] = {
    0x08080808, // 8.8.8.8 (Google)
    0x08080404, // 8.8.4.4 (Google)
    0x01010101, // 1.1.1.1 (Cloudflare)
    0x01000001, // 1.0.0.1 (Cloudflare)
    0x09090909, // 9.9.9.9 (Quad9)
    0x95858585, // 149.112.112.112 (Quad9)
    0xD043D043, // 208.67.220.67 (OpenDNS)
    0xD043D044, // 208.67.220.68 (OpenDNS)
};

// Certificate pinning structure
typedef struct {
    char hostname[256];
    uint8_t pin_sha256[SHA256_DIGEST_LENGTH];
    bool wildcard_match;
    uint64_t expiry_timestamp;
} cert_pin_t;

// Static certificate pins - in production, these would be loaded from configuration
static cert_pin_t PINNED_CERTS[MAX_PINNED_CERTS] = {
    // Example pins - these would be real certificate hashes in production
    {
        .hostname = "google.com",
        .pin_sha256 = {0x2B, 0x0C, 0x1C, 0x59, 0xA0, 0xA0, 0xAE, 0x76, 
                      0xB0, 0xEA, 0xDB, 0x2B, 0xAB, 0x48, 0xEE, 0xB4, 
                      0x16, 0x05, 0x6C, 0xC3, 0x60, 0x1B, 0x63, 0x0C, 
                      0x2E, 0xAF, 0x06, 0x13, 0xAF, 0xA8, 0x3F, 0x92},
        .wildcard_match = true,
        .expiry_timestamp = 0 // 0 = no expiry
    }
    // Additional pins would be added here
};
static size_t PINNED_CERT_COUNT = 1;

struct privacy_guards {
    bool dns_leak_protection_enabled;
    bool ipv6_leak_protection_enabled;
    bool webrtc_leak_protection_enabled;
    bool kill_switch_enabled;
    bool kill_switch_active;
    
    // VPN configuration context for proper leak detection
    bool vpn_supports_ipv4;
    bool vpn_supports_ipv6;
    bool vpn_tunnel_active;
    
    ip_addr_t allowed_dns_servers[MAX_ALLOWED_DNS_SERVERS];
    size_t allowed_dns_server_count;
    
    privacy_violation_t recent_violations[MAX_RECENT_VIOLATIONS];
    size_t violation_count;
    size_t violation_write_index;
    
    privacy_violation_callback_t violation_callback;
    void *callback_user_data;
    
    dns_leak_status_t dns_leak_status;
    pthread_mutex_t mutex;
    privacy_stats_t stats;
};

static bool privacy_is_dns_packet(const uint8_t *packet, size_t length, const flow_tuple_t *flow);
static bool privacy_is_webrtc_packet(const uint8_t *packet, size_t length, const flow_tuple_t *flow);
static bool privacy_is_allowed_dns_server(privacy_guards_t *guards, const ip_addr_t *server);
static bool privacy_is_known_doh_provider(const ip_addr_t *server);
static bool privacy_extract_public_key_hash(const uint8_t *cert_data, size_t cert_length, uint8_t *hash_out);
static bool privacy_hostname_matches_pin(const char *hostname, const cert_pin_t *pin);
static void privacy_record_violation(privacy_guards_t *guards, privacy_violation_type_t type,
                                   const flow_tuple_t *flow, const char *description, bool blocked);
static void privacy_activate_kill_switch(privacy_guards_t *guards, const char *reason);
static bool privacy_guards_is_legitimate_ipv6_traffic(privacy_guards_t *guards, const flow_tuple_t *flow);

privacy_guards_t *privacy_guards_create(void) {
    privacy_guards_t *guards = calloc(1, sizeof(privacy_guards_t));
    if (!guards) {
        LOG_ERROR("Failed to allocate privacy guards");
        return NULL;
    }
    
    if (pthread_mutex_init(&guards->mutex, NULL) != 0) {
        LOG_ERROR("Failed to initialize privacy guards mutex");
        free(guards);
        return NULL;
    }
    
    guards->dns_leak_protection_enabled = true;
    guards->ipv6_leak_protection_enabled = true;
    guards->webrtc_leak_protection_enabled = false;
    guards->kill_switch_enabled = true;
    guards->kill_switch_active = false;
    guards->dns_leak_status = DNS_LEAK_STATUS_NONE;
    
    // Initialize VPN configuration context (will be updated by VPN engine)
    guards->vpn_supports_ipv4 = true;   // Default to dual-stack
    guards->vpn_supports_ipv6 = true;
    guards->vpn_tunnel_active = false;
    
    LOG_INFO("Privacy guards created with default protections enabled");
    return guards;
}

void privacy_guards_destroy(privacy_guards_t *guards) {
    if (!guards) return;
    
    pthread_mutex_lock(&guards->mutex);
    
    privacy_guards_secure_zero(guards->recent_violations, sizeof(guards->recent_violations));
    privacy_guards_secure_zero(guards->allowed_dns_servers, sizeof(guards->allowed_dns_servers));
    
    pthread_mutex_unlock(&guards->mutex);
    pthread_mutex_destroy(&guards->mutex);
    
    privacy_guards_secure_zero(guards, sizeof(privacy_guards_t));
    free(guards);
    
    LOG_INFO("Privacy guards destroyed");
}

bool privacy_guards_enable_dns_leak_protection(privacy_guards_t *guards, bool enable) {
    if (!guards) return false;
    
    pthread_mutex_lock(&guards->mutex);
    guards->dns_leak_protection_enabled = enable;
    pthread_mutex_unlock(&guards->mutex);
    
    LOG_INFO("DNS leak protection %s", enable ? "enabled" : "disabled");
    return true;
}

bool privacy_guards_enable_ipv6_leak_protection(privacy_guards_t *guards, bool enable) {
    if (!guards) return false;
    
    pthread_mutex_lock(&guards->mutex);
    guards->ipv6_leak_protection_enabled = enable;
    pthread_mutex_unlock(&guards->mutex);
    
    LOG_INFO("IPv6 leak protection %s", enable ? "enabled" : "disabled");
    return true;
}

bool privacy_guards_enable_webrtc_leak_protection(privacy_guards_t *guards, bool enable) {
    if (!guards) return false;
    
    pthread_mutex_lock(&guards->mutex);
    guards->webrtc_leak_protection_enabled = enable;
    pthread_mutex_unlock(&guards->mutex);
    
    LOG_INFO("WebRTC leak protection %s", enable ? "enabled" : "disabled");
    return true;
}

bool privacy_guards_enable_kill_switch(privacy_guards_t *guards, bool enable) {
    if (!guards) return false;
    
    pthread_mutex_lock(&guards->mutex);
    guards->kill_switch_enabled = enable;
    if (!enable) {
        guards->kill_switch_active = false;
    }
    pthread_mutex_unlock(&guards->mutex);
    
    LOG_INFO("Kill switch %s", enable ? "enabled" : "disabled");
    return true;
}

bool privacy_guards_set_allowed_dns_servers(privacy_guards_t *guards, const ip_addr_t *servers, size_t count) {
    if (!guards || !servers || count > MAX_ALLOWED_DNS_SERVERS) return false;
    
    pthread_mutex_lock(&guards->mutex);
    
    memcpy(guards->allowed_dns_servers, servers, count * sizeof(ip_addr_t));
    guards->allowed_dns_server_count = count;
    
    pthread_mutex_unlock(&guards->mutex);
    
    LOG_INFO("Set %zu allowed DNS servers", count);
    return true;
}

bool privacy_guards_add_allowed_dns_server(privacy_guards_t *guards, const ip_addr_t *server) {
    if (!guards || !server) return false;
    
    pthread_mutex_lock(&guards->mutex);
    
    if (guards->allowed_dns_server_count >= MAX_ALLOWED_DNS_SERVERS) {
        pthread_mutex_unlock(&guards->mutex);
        LOG_WARN("Maximum allowed DNS servers reached");
        return false;
    }
    
    guards->allowed_dns_servers[guards->allowed_dns_server_count++] = *server;
    
    pthread_mutex_unlock(&guards->mutex);
    
    LOG_DEBUG("Added allowed DNS server");
    return true;
}

bool privacy_guards_inspect_packet(privacy_guards_t *guards, const uint8_t *packet, size_t length,
                                 const flow_tuple_t *flow, bool *should_block) {
    if (!guards || !packet || !flow || !should_block) return false;
    
    *should_block = false;
    
    pthread_mutex_lock(&guards->mutex);
    
    guards->stats.packets_inspected++;
    
    if (guards->kill_switch_active) {
        *should_block = true;
        guards->stats.packets_blocked++;
        pthread_mutex_unlock(&guards->mutex);
        return true;
    }
    
    // Check for DNS leaks (including DoH/DoT)
    if (guards->dns_leak_protection_enabled && privacy_is_dns_packet(packet, length, flow)) {
        bool is_authorized = privacy_is_allowed_dns_server(guards, &flow->dst_ip);
        
        if (!is_authorized) {
            guards->dns_leak_status = DNS_LEAK_STATUS_DETECTED;
            guards->stats.dns_leaks_detected++;
            
            // SECURITY FIX: Enhanced violation reporting for different DNS types
            const char *dns_type = "Standard DNS";
            if (flow->dst_port == 853) {
                dns_type = (flow->protocol == PROTO_TCP) ? "DNS over TLS (DoT)" : "DNS over QUIC (DoQ)";
            } else if (flow->dst_port == 443) {
                dns_type = "DNS over HTTPS (DoH)";
            }
            
            char violation_desc[256];
            snprintf(violation_desc, sizeof(violation_desc), 
                    "%s query to unauthorized server (port %d)", dns_type, flow->dst_port);
            
            if (guards->kill_switch_enabled) {
                privacy_activate_kill_switch(guards, violation_desc);
                *should_block = true;
                guards->stats.dns_leaks_blocked++;
                guards->stats.packets_blocked++;
                
                privacy_record_violation(guards, PRIVACY_VIOLATION_DNS_LEAK, flow,
                                       violation_desc, true);
            } else {
                privacy_record_violation(guards, PRIVACY_VIOLATION_DNS_LEAK, flow,
                                       violation_desc, false);
            }
        }
    }
    
    // Check for IPv6 leaks - only block if VPN is configured as IPv4-only
    // Note: This requires VPN configuration context to determine if IPv6 is supported
    // For now, we implement intelligent IPv6 leak detection that considers:
    // 1. Whether the VPN tunnel supports IPv6
    // 2. Whether this IPv6 traffic is bypassing the VPN inappropriately
    if (guards->ipv6_leak_protection_enabled && flow->ip_version == 6) {
        bool is_legitimate_ipv6 = privacy_guards_is_legitimate_ipv6_traffic(guards, flow);
        
        if (!is_legitimate_ipv6) {
            guards->stats.ipv6_leaks_detected++;
            
            if (guards->kill_switch_enabled) {
                *should_block = true;
                guards->stats.ipv6_leaks_blocked++;
                guards->stats.packets_blocked++;
                
                privacy_record_violation(guards, PRIVACY_VIOLATION_IPV6_LEAK, flow,
                                       "IPv6 traffic bypassing VPN tunnel detected", true);
            } else {
                privacy_record_violation(guards, PRIVACY_VIOLATION_IPV6_LEAK, flow,
                                       "IPv6 traffic bypassing VPN tunnel detected", false);
            }
        }
    }
    
    // Check for WebRTC leaks
    if (guards->webrtc_leak_protection_enabled && privacy_is_webrtc_packet(packet, length, flow)) {
        guards->stats.webrtc_leaks_detected++;
        
        if (guards->kill_switch_enabled) {
            *should_block = true;
            guards->stats.webrtc_leaks_blocked++;
            guards->stats.packets_blocked++;
            
            privacy_record_violation(guards, PRIVACY_VIOLATION_WEBRTC_LEAK, flow,
                                   "WebRTC STUN/TURN traffic detected", true);
        } else {
            privacy_record_violation(guards, PRIVACY_VIOLATION_WEBRTC_LEAK, flow,
                                   "WebRTC STUN/TURN traffic detected", false);
        }
    }
    
    // Check for unencrypted DNS (only for authorized servers - unauthorized already flagged as leaks)
    if (privacy_is_dns_packet(packet, length, flow) && flow->dst_port == DNS_PORT) {
        bool is_authorized = privacy_is_allowed_dns_server(guards, &flow->dst_ip);
        
        if (is_authorized) {
            guards->stats.unencrypted_dns_queries++;
            
            privacy_record_violation(guards, PRIVACY_VIOLATION_UNENCRYPTED_DNS, flow,
                                   "Unencrypted DNS query detected", false);
        }
    }
    
    // SECURITY FIX: Check TLS connections for minimum version compliance
    if (flow->protocol == PROTO_TCP && (flow->dst_port == 443 || flow->dst_port == 8443)) {
        if (length >= 5 && packet[0] == 0x16) { // TLS Handshake
            if (!privacy_guards_validate_tls_connection(guards, packet, length)) {
                // TLS version is too weak
                if (guards->kill_switch_enabled) {
                    *should_block = true;
                    guards->stats.packets_blocked++;
                    
                    privacy_record_violation(guards, PRIVACY_VIOLATION_WEAK_ENCRYPTION, flow,
                                           "TLS connection blocked due to weak encryption", true);
                } else {
                    privacy_record_violation(guards, PRIVACY_VIOLATION_WEAK_ENCRYPTION, flow,
                                           "TLS connection with weak encryption detected", false);
                }
            }
        }
    }
    
    pthread_mutex_unlock(&guards->mutex);
    return true;
}

dns_leak_status_t privacy_guards_get_dns_leak_status(privacy_guards_t *guards) {
    if (!guards) return DNS_LEAK_STATUS_NONE;
    
    pthread_mutex_lock(&guards->mutex);
    dns_leak_status_t status = guards->dns_leak_status;
    pthread_mutex_unlock(&guards->mutex);
    
    return status;
}

bool privacy_guards_is_kill_switch_active(privacy_guards_t *guards) {
    if (!guards) return false;
    
    pthread_mutex_lock(&guards->mutex);
    bool active = guards->kill_switch_active;
    pthread_mutex_unlock(&guards->mutex);
    
    return active;
}

void privacy_guards_set_violation_callback(privacy_guards_t *guards, privacy_violation_callback_t callback, void *user_data) {
    if (!guards) return;
    
    pthread_mutex_lock(&guards->mutex);
    guards->violation_callback = callback;
    guards->callback_user_data = user_data;
    pthread_mutex_unlock(&guards->mutex);
}

void privacy_guards_clear_memory(void *ptr, size_t size) {
    if (!ptr || size == 0) return;
    
    volatile uint8_t *vptr = (volatile uint8_t *)ptr;
    for (size_t i = 0; i < size; i++) {
        vptr[i] = 0;
    }
}

void privacy_guards_secure_zero(void *ptr, size_t size) {
    privacy_guards_clear_memory(ptr, size);
    
    __asm__ __volatile__("" ::: "memory");
}

bool privacy_guards_validate_tls_connection(privacy_guards_t *guards, const uint8_t *tls_data, size_t length) {
    if (!guards || !tls_data || length < 5) return false;
    
    // Check if this is a valid TLS record type
    uint8_t record_type = tls_data[0];
    if (record_type < 0x14 || record_type > 0x18) {
        // Invalid TLS record type (valid range: 20-24)
        LOG_WARN("Invalid TLS record type: 0x%02x", record_type);
        return false;
    }
    
    // Extract TLS version from all record types
    uint16_t version = (tls_data[1] << 8) | tls_data[2];
    
    // SECURITY FIX: Enforce minimum TLS 1.2 (0x0303) for all TLS traffic
    if (version < 0x0303) { // Anything below TLS 1.2
        pthread_mutex_lock(&guards->mutex);
        guards->stats.weak_encryption_detected++;
        pthread_mutex_unlock(&guards->mutex);
        
        const char *version_name = "Unknown";
        switch (version) {
            case 0x0300: version_name = "SSL 3.0"; break;
            case 0x0301: version_name = "TLS 1.0"; break;
            case 0x0302: version_name = "TLS 1.1"; break;
            default: version_name = "Unknown/Invalid"; break;
        }
        
        LOG_WARN("Weak TLS version detected: %s (0x%04x) - minimum TLS 1.2 required", 
                version_name, version);
        return false;
    }
    
    // Validate known TLS versions
    if (version != 0x0303 && version != 0x0304) {
        LOG_WARN("Unknown/Invalid TLS version: 0x%04x", version);
        return false;
    }
    
    // Log acceptable TLS versions for monitoring
    if (version == 0x0303) {
        LOG_DEBUG("TLS 1.2 connection accepted");
    } else if (version == 0x0304) {
        LOG_DEBUG("TLS 1.3 connection accepted");
    }
    
    return true;
}

void privacy_guards_get_stats(privacy_guards_t *guards, privacy_stats_t *stats) {
    if (!guards || !stats) return;
    
    pthread_mutex_lock(&guards->mutex);
    *stats = guards->stats;
    pthread_mutex_unlock(&guards->mutex);
}

void privacy_guards_reset_stats(privacy_guards_t *guards) {
    if (!guards) return;
    
    pthread_mutex_lock(&guards->mutex);
    memset(&guards->stats, 0, sizeof(privacy_stats_t));
    pthread_mutex_unlock(&guards->mutex);
    
    LOG_DEBUG("Privacy guards stats reset");
}

static bool privacy_is_dns_packet(const uint8_t *packet, size_t length, const flow_tuple_t *flow) {
    // Standard DNS (port 53)
    if ((flow->protocol == PROTO_UDP && flow->dst_port == DNS_PORT) ||
        (flow->protocol == PROTO_TCP && flow->dst_port == DNS_PORT)) {
        return true;
    }
    
    // SECURITY FIX: Enhanced DNS leak detection for DoH/DoT
    
    // DNS over TLS (DoT) - port 853
    if (flow->protocol == PROTO_TCP && flow->dst_port == 853) {
        return true;
    }
    
    // DNS over HTTPS (DoH) - port 443 with specific patterns or known providers
    if (flow->protocol == PROTO_TCP && flow->dst_port == 443) {
        // Check if destination is a known DoH provider
        if (privacy_is_known_doh_provider(&flow->dst_ip)) {
            return true;
        }
        
        // Look for DoH patterns in the packet data
        if (length >= 5 && packet[0] == 0x16) { // TLS handshake
            // Additional DoH detection based on SNI or other indicators
            // For conservative detection, we check known DoH provider IPs above
        }
        
        // Check for HTTP/2 patterns (DoH commonly uses HTTP/2)
        if (length >= 24) {
            // HTTP/2 connection preface: "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
            const char http2_preface[] = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
            if (memcmp(packet, http2_preface, 24) == 0 && 
                privacy_is_known_doh_provider(&flow->dst_ip)) {
                return true; // DoH traffic to known provider
            }
        }
    }
    
    // DNS over QUIC (DoQ) - typically port 853 over UDP
    if (flow->protocol == PROTO_UDP && flow->dst_port == 853) {
        // QUIC packets have specific header patterns
        if (length > 0 && (packet[0] & 0x80) != 0) { // QUIC long header
            return true;
        }
    }
    
    // Alternative DoH ports (some providers use 8443, 8453, etc.)
    if (flow->protocol == PROTO_TCP && (flow->dst_port == 8443 || flow->dst_port == 8453)) {
        return true;
    }
    
    return false;
}

static bool privacy_is_webrtc_packet(const uint8_t *packet, size_t length, const flow_tuple_t *flow) {
    // SECURITY FIX: Enhanced WebRTC detection
    
    // Standard STUN/TURN ports (UDP and TCP)
    uint16_t port = flow->dst_port;
    if ((port >= WEBRTC_STUN_PORT_START && port <= WEBRTC_STUN_PORT_END) ||
        port == 5349 || // TURN over TLS
        port == 5350) { // TURN over DTLS
        return true;
    }
    
    // Check for STUN packet signatures
    if (length >= 20 && flow->protocol == PROTO_UDP) {
        // STUN messages start with specific magic values
        uint16_t msg_type = (packet[0] << 8) | packet[1];
        uint16_t msg_length = (packet[2] << 8) | packet[3];
        uint32_t magic_cookie = (packet[4] << 24) | (packet[5] << 16) | 
                               (packet[6] << 8) | packet[7];
        
        // STUN magic cookie: 0x2112A442
        if (magic_cookie == 0x2112A442) {
            // Validate STUN message types
            uint16_t msg_class = (msg_type & 0x0110) >> 4;
            uint16_t msg_method = (msg_type & 0x000F) | ((msg_type & 0x00E0) >> 1) | 
                                 ((msg_type & 0x3E00) >> 2);
            
            // Common STUN methods: Binding (0x001), Allocate (0x003), etc.
            if (msg_method <= 0x00B && msg_class <= 0x03) {
                return true;
            }
        }
    }
    
    // Check for WebRTC data channel patterns (DTLS-SRTP)
    if (length >= 13 && flow->protocol == PROTO_UDP) {
        // DTLS handshake packets
        if (packet[0] >= 20 && packet[0] <= 23) { // DTLS content types
            uint16_t version = (packet[1] << 8) | packet[2];
            // DTLS 1.0 (0xFEFF) or DTLS 1.2 (0xFEFD)
            if (version == 0xFEFF || version == 0xFEFD) {
                return true;
            }
        }
        
        // SRTP/SRTCP packets (RTP with extension)
        if (length >= 12) {
            uint8_t version = (packet[0] & 0xC0) >> 6;
            uint8_t payload_type = packet[1] & 0x7F;
            
            if (version == 2) { // RTP version 2
                // Common RTP payload types used by WebRTC
                if ((payload_type >= 96 && payload_type <= 127) || // Dynamic payload types
                    payload_type == 0 ||   // PCMU
                    payload_type == 8 ||   // PCMA
                    payload_type == 9 ||   // G722
                    payload_type == 111) { // Opus (common WebRTC codec)
                    return true;
                }
            }
        }
    }
    
    // Check for WebRTC signaling over non-standard ports
    if (flow->protocol == PROTO_TCP) {
        // WebRTC can use any TCP port for signaling
        // Look for WebSocket upgrade patterns (common for WebRTC signaling)
        if (length >= 16) {
            const char *websocket_upgrade = "Upgrade: websocket";
            if (memmem(packet, length, websocket_upgrade, strlen(websocket_upgrade))) {
                return true;
            }
            
            // Check for WebRTC-specific signaling patterns
            const char *webrtc_patterns[] = {
                "candidate:",
                "a=ice-pwd:",
                "a=ice-ufrag:",
                "a=fingerprint:",
                "m=audio",
                "m=video",
                "a=sendrecv",
                "a=recvonly",
                "a=sendonly"
            };
            
            for (size_t i = 0; i < sizeof(webrtc_patterns) / sizeof(webrtc_patterns[0]); i++) {
                if (memmem(packet, length, webrtc_patterns[i], strlen(webrtc_patterns[i]))) {
                    return true;
                }
            }
        }
    }
    
    return false;
}

static bool privacy_is_allowed_dns_server(privacy_guards_t *guards, const ip_addr_t *server) {
    for (size_t i = 0; i < guards->allowed_dns_server_count; i++) {
        const ip_addr_t *allowed = &guards->allowed_dns_servers[i];
        
        if (server->v4.addr != 0 && allowed->v4.addr != 0) {
            if (server->v4.addr == allowed->v4.addr) return true;
        } else if (server->v4.addr == 0 && allowed->v4.addr == 0) {
            if (memcmp(server->v6.addr, allowed->v6.addr, 16) == 0) return true;
        }
    }
    
    return false;
}

static bool privacy_is_known_doh_provider(const ip_addr_t *server) {
    if (!server) return false;
    
    // Check IPv4 addresses
    if (server->v4.addr != 0) {
        uint32_t addr = ntohl(server->v4.addr);
        size_t count = sizeof(KNOWN_DOH_IPV4) / sizeof(KNOWN_DOH_IPV4[0]);
        
        for (size_t i = 0; i < count; i++) {
            if (addr == KNOWN_DOH_IPV4[i]) {
                return true;
            }
        }
    }
    
    // TODO: Add IPv6 DoH provider addresses when needed
    // Common IPv6 DoH providers:
    // 2001:4860:4860::8888 (Google)
    // 2606:4700:4700::1111 (Cloudflare)
    // etc.
    
    return false;
}

static void privacy_record_violation(privacy_guards_t *guards, privacy_violation_type_t type,
                                   const flow_tuple_t *flow, const char *description, bool blocked) {
    privacy_violation_t *violation = &guards->recent_violations[guards->violation_write_index];
    
    memset(violation, 0, sizeof(privacy_violation_t));
    violation->type = type;
    violation->source_addr = flow->src_ip;
    violation->destination_addr = flow->dst_ip;
    violation->source_port = flow->src_port;
    violation->destination_port = flow->dst_port;
    violation->protocol = flow->protocol;
    violation->timestamp_ns = clock_gettime_nsec_np(CLOCK_MONOTONIC);
    violation->blocked = blocked;
    
    strncpy(violation->description, description, sizeof(violation->description) - 1);
    
    guards->violation_write_index = (guards->violation_write_index + 1) % MAX_RECENT_VIOLATIONS;
    if (guards->violation_count < MAX_RECENT_VIOLATIONS) {
        guards->violation_count++;
    }
    
    guards->stats.total_violations++;
    
    if (guards->violation_callback) {
        guards->violation_callback(violation, guards->callback_user_data);
    }
    
    privacy_guards_log_redacted("Privacy violation: %s", description);
}

static void privacy_activate_kill_switch(privacy_guards_t *guards, const char *reason) {
    if (!guards->kill_switch_enabled) return;
    
    guards->kill_switch_active = true;
    guards->dns_leak_status = DNS_LEAK_STATUS_KILL_SWITCH_ACTIVE;
    guards->stats.kill_switch_activations++;
    
    LOG_WARN("Kill switch activated: %s", reason);
}

const char *privacy_violation_type_string(privacy_violation_type_t type) {
    switch (type) {
        case PRIVACY_VIOLATION_DNS_LEAK: return "DNS Leak";
        case PRIVACY_VIOLATION_IPV6_LEAK: return "IPv6 Leak";
        case PRIVACY_VIOLATION_WEBRTC_LEAK: return "WebRTC Leak";
        case PRIVACY_VIOLATION_UNENCRYPTED_DNS: return "Unencrypted DNS";
        case PRIVACY_VIOLATION_WEAK_ENCRYPTION: return "Weak Encryption";
        default: return "Unknown";
    }
}

const char *dns_leak_status_string(dns_leak_status_t status) {
    switch (status) {
        case DNS_LEAK_STATUS_NONE: return "None";
        case DNS_LEAK_STATUS_DETECTED: return "Detected";
        case DNS_LEAK_STATUS_BLOCKED: return "Blocked";
        case DNS_LEAK_STATUS_KILL_SWITCH_ACTIVE: return "Kill Switch Active";
        default: return "Unknown";
    }
}

bool privacy_guards_export_violations(privacy_guards_t *guards, privacy_violation_t *violations, 
                                     size_t max_count, size_t *actual_count) {
    if (!guards || !violations || !actual_count) return false;
    
    pthread_mutex_lock(&guards->mutex);
    
    size_t count = guards->violation_count;
    if (count > max_count) count = max_count;
    
    for (size_t i = 0; i < count; i++) {
        size_t index = (guards->violation_write_index - count + i) % MAX_RECENT_VIOLATIONS;
        violations[i] = guards->recent_violations[index];
    }
    
    *actual_count = count;
    
    pthread_mutex_unlock(&guards->mutex);
    return true;
}

bool privacy_guards_is_dns_leak_protection_enabled(privacy_guards_t *guards) {
    if (!guards) return false;
    
    pthread_mutex_lock(&guards->mutex);
    bool enabled = guards->dns_leak_protection_enabled;
    pthread_mutex_unlock(&guards->mutex);
    
    return enabled;
}

bool privacy_guards_is_ipv6_leak_protection_enabled(privacy_guards_t *guards) {
    if (!guards) return false;
    
    pthread_mutex_lock(&guards->mutex);
    bool enabled = guards->ipv6_leak_protection_enabled;
    pthread_mutex_unlock(&guards->mutex);
    
    return enabled;
}

bool privacy_guards_is_webrtc_leak_protection_enabled(privacy_guards_t *guards) {
    if (!guards) return false;
    
    pthread_mutex_lock(&guards->mutex);
    bool enabled = guards->webrtc_leak_protection_enabled;
    pthread_mutex_unlock(&guards->mutex);
    
    return enabled;
}

bool privacy_guards_is_kill_switch_enabled(privacy_guards_t *guards) {
    if (!guards) return false;
    
    pthread_mutex_lock(&guards->mutex);
    bool enabled = guards->kill_switch_enabled;
    pthread_mutex_unlock(&guards->mutex);
    
    return enabled;
}

bool privacy_guards_remove_allowed_dns_server(privacy_guards_t *guards, const ip_addr_t *server) {
    if (!guards || !server) return false;
    
    pthread_mutex_lock(&guards->mutex);
    
    for (size_t i = 0; i < guards->allowed_dns_server_count; i++) {
        ip_addr_t *existing = &guards->allowed_dns_servers[i];
        
        bool match = false;
        if (server->v4.addr != 0 && existing->v4.addr != 0) {
            match = (server->v4.addr == existing->v4.addr);
        } else if (server->v4.addr == 0 && existing->v4.addr == 0) {
            match = (memcmp(server->v6.addr, existing->v6.addr, 16) == 0);
        }
        
        if (match) {
            memmove(&guards->allowed_dns_servers[i], &guards->allowed_dns_servers[i + 1],
                   (guards->allowed_dns_server_count - i - 1) * sizeof(ip_addr_t));
            guards->allowed_dns_server_count--;
            pthread_mutex_unlock(&guards->mutex);
            return true;
        }
    }
    
    pthread_mutex_unlock(&guards->mutex);
    return false;
}

bool privacy_guards_check_certificate_pinning(privacy_guards_t *guards, const char *hostname, 
                                             const uint8_t *cert_data, size_t cert_length) {
    if (!guards || !hostname || !cert_data || cert_length == 0) return false;
    
    // SECURITY FIX: Proper certificate pinning implementation
    LOG_DEBUG("Certificate pinning check for hostname: %s", hostname);
    
    pthread_mutex_lock(&guards->mutex);
    
    // Find matching pin for this hostname
    const cert_pin_t *matching_pin = NULL;
    for (size_t i = 0; i < PINNED_CERT_COUNT; i++) {
        if (privacy_hostname_matches_pin(hostname, &PINNED_CERTS[i])) {
            // Check if pin has expired
            if (PINNED_CERTS[i].expiry_timestamp > 0) {
                uint64_t current_time = clock_gettime_nsec_np(CLOCK_MONOTONIC) / 1000000000ULL;
                if (current_time > PINNED_CERTS[i].expiry_timestamp) {
                    LOG_WARN("Certificate pin for %s has expired", hostname);
                    continue;
                }
            }
            
            matching_pin = &PINNED_CERTS[i];
            break;
        }
    }
    
    pthread_mutex_unlock(&guards->mutex);
    
    if (!matching_pin) {
        LOG_DEBUG("No certificate pin found for hostname: %s", hostname);
        return true; // No pin required - allow connection
    }
    
    // Extract public key hash from certificate
    uint8_t cert_hash[SHA256_DIGEST_LENGTH];
    if (!privacy_extract_public_key_hash(cert_data, cert_length, cert_hash)) {
        LOG_ERROR("Failed to extract public key hash from certificate for %s", hostname);
        
        pthread_mutex_lock(&guards->mutex);
        guards->stats.certificate_validation_failures++;
        pthread_mutex_unlock(&guards->mutex);
        
        return false; // Failed to extract hash - reject connection
    }
    
    // Compare extracted hash with pinned hash
    if (memcmp(cert_hash, matching_pin->pin_sha256, SHA256_DIGEST_LENGTH) == 0) {
        LOG_INFO("Certificate pin validation successful for %s", hostname);
        
        pthread_mutex_lock(&guards->mutex);
        guards->stats.certificate_pins_validated++;
        pthread_mutex_unlock(&guards->mutex);
        
        return true; // Pin matches - allow connection
    }
    
    // Pin mismatch - this is a security violation
    LOG_ERROR("Certificate pin mismatch for %s - potential MITM attack", hostname);
    
    pthread_mutex_lock(&guards->mutex);
    guards->stats.certificate_pin_failures++;
    pthread_mutex_unlock(&guards->mutex);
    
    return false; // Pin mismatch - reject connection
}

// PRODUCTION FIX: Hardened ASN.1 length parsing with comprehensive security validation
static bool asn1_parse_length(const uint8_t **data, const uint8_t *end, size_t *length, size_t max_length) {
    if (!data || !*data || !end || !length || *data >= end) {
        return false;
    }
    
    uint8_t first_byte = **data;
    (*data)++;
    
    if ((first_byte & 0x80) == 0) {
        // Short form - length is in the first byte
        *length = first_byte;
        
        // SECURITY FIX: Validate short form length against maximum
        if (*length > max_length) {
            LOG_ERROR("ASN.1 short form length %zu exceeds maximum %zu", *length, max_length);
            return false;
        }
        
        return true;
    }
    
    // Long form - first byte indicates how many bytes encode the length
    size_t length_bytes = first_byte & 0x7F;
    
    // SECURITY FIX: Comprehensive validation of long form encoding
    if (length_bytes == 0) {
        LOG_ERROR("ASN.1 indefinite length not supported for security reasons");
        return false;
    }
    
    if (length_bytes > sizeof(size_t)) {
        LOG_ERROR("ASN.1 length encoding too large: %zu bytes", length_bytes);
        return false;
    }
    
    if (*data + length_bytes > end) {
        LOG_ERROR("ASN.1 length encoding extends beyond data");
        return false;
    }
    
    // SECURITY FIX: Prevent integer overflow in length calculation
    *length = 0;
    for (size_t i = 0; i < length_bytes; i++) {
        // Check for overflow before shifting
        if (*length > (SIZE_MAX >> 8)) {
            LOG_ERROR("ASN.1 length overflow during parsing");
            return false;
        }
        
        *length = (*length << 8) | **data;
        (*data)++;
        
        // Additional overflow check after each byte
        if (*length > max_length) {
            LOG_ERROR("ASN.1 length %zu exceeds maximum %zu during parsing", *length, max_length);
            return false;
        }
    }
    
    // SECURITY FIX: Final validation against available data and maximum length
    size_t remaining_data = (size_t)(end - *data);
    if (*length > remaining_data) {
        LOG_ERROR("ASN.1 length %zu exceeds remaining data %zu", *length, remaining_data);
        return false;
    }
    
    return true;
}

static bool asn1_skip_tag_and_length(const uint8_t **data, const uint8_t *end, uint8_t expected_tag, size_t max_length) {
    if (!data || !*data || !end || *data >= end || **data != expected_tag) {
        return false;
    }
    (*data)++; // Skip tag
    
    size_t length;
    if (!asn1_parse_length(data, end, &length, max_length)) {
        return false;
    }
    
    // SECURITY FIX: Validate that we can safely skip this much data
    if (*data + length > end) {
        LOG_ERROR("ASN.1 skip operation would exceed data bounds");
        return false;
    }
    
    *data += length;
    return true;
}

static bool privacy_extract_public_key_hash(const uint8_t *cert_data, size_t cert_length, uint8_t *hash_out) {
    if (!cert_data || cert_length == 0 || !hash_out) return false;
    
    // SECURITY FIX: Proper X.509 certificate parsing for SPKI extraction
    const uint8_t *data = cert_data;
    const uint8_t *end = cert_data + cert_length;
    
    // X.509 Certificate structure:
    // Certificate ::= SEQUENCE {
    //     tbsCertificate       TBSCertificate,
    //     signatureAlgorithm   AlgorithmIdentifier,
    //     signatureValue       BIT STRING
    // }
    
    // Parse outer SEQUENCE tag for Certificate
    size_t cert_total_length;
    if (*data != 0x30) {
        LOG_ERROR("Invalid X.509 certificate: missing outer SEQUENCE tag");
        return false;
    }
    data++; // Skip tag
    
    if (!asn1_parse_length(&data, end, &cert_total_length, cert_length)) {
        LOG_ERROR("Invalid X.509 certificate: malformed outer SEQUENCE length");
        return false;
    }
    
    // Parse TBSCertificate SEQUENCE
    const uint8_t *tbs_start = data; // SECURITY FIX: Safe TBS start tracking
    size_t tbs_length;
    if (*data != 0x30) {
        LOG_ERROR("Invalid X.509 certificate: missing TBSCertificate SEQUENCE tag");
        return false;
    }
    data++; // Skip tag
    
    if (!asn1_parse_length(&data, end, &tbs_length, (size_t)(end - data))) {
        LOG_ERROR("Invalid X.509 certificate: malformed TBSCertificate SEQUENCE length");
        return false;
    }
    
    // Skip version (optional, context-specific [0])
    if (data < end && *data == 0xA0) {
        if (!asn1_skip_tag_and_length(&data, end, 0xA0, (size_t)(end - data))) {
            LOG_ERROR("Invalid X.509 certificate: malformed version field");
            return false;
        }
    }
    
    // Skip serialNumber (INTEGER)
    if (!asn1_skip_tag_and_length(&data, end, 0x02, (size_t)(end - data))) {
        LOG_ERROR("Invalid X.509 certificate: missing serial number");
        return false;
    }
    
    // Skip signature algorithm (SEQUENCE)
    if (!asn1_skip_tag_and_length(&data, end, 0x30, (size_t)(end - data))) {
        LOG_ERROR("Invalid X.509 certificate: missing signature algorithm");
        return false;
    }
    
    // Skip issuer (SEQUENCE)  
    if (!asn1_skip_tag_and_length(&data, end, 0x30, (size_t)(end - data))) {
        LOG_ERROR("Invalid X.509 certificate: missing issuer");
        return false;
    }
    
    // Skip validity (SEQUENCE)
    if (!asn1_skip_tag_and_length(&data, end, 0x30, (size_t)(end - data))) {
        LOG_ERROR("Invalid X.509 certificate: missing validity");
        return false;
    }
    
    // Skip subject (SEQUENCE)
    if (!asn1_skip_tag_and_length(&data, end, 0x30, (size_t)(end - data))) {
        LOG_ERROR("Invalid X.509 certificate: missing subject");
        return false;
    }
    
    // NOW we're at the SubjectPublicKeyInfo (SPKI) - this is what we want to hash!
    if (data >= end || *data != 0x30) {
        LOG_ERROR("Invalid X.509 certificate: missing SubjectPublicKeyInfo");
        return false;
    }
    
    const uint8_t *spki_start = data;
    data++; // Skip SEQUENCE tag
    
    size_t spki_length;
    if (!asn1_parse_length(&data, end, &spki_length, (size_t)(end - data))) {
        LOG_ERROR("Invalid X.509 certificate: malformed SubjectPublicKeyInfo length");
        return false;
    }
    
    // SECURITY FIX: Validate SPKI data bounds before computing hash
    if (spki_start + spki_length + (data - spki_start) > end) {
        LOG_ERROR("SubjectPublicKeyInfo extends beyond certificate data");
        return false;
    }
    
    // Total SPKI length includes the tag and length bytes
    size_t total_spki_length = (data - spki_start) + spki_length;
    
    // SECURITY FIX: Additional validation before hashing
    if (total_spki_length == 0 || total_spki_length > MAX_CERTIFICATE_SIZE) {
        LOG_ERROR("Invalid SPKI length: %zu", total_spki_length);
        return false;
    }
    
    // SECURITY FIX: Compute SHA-256 hash of the complete SPKI (tag + length + content)
    CC_SHA256_CTX context;
    CC_SHA256_Init(&context);
    CC_SHA256_Update(&context, spki_start, (CC_LONG)total_spki_length);
    CC_SHA256_Final(hash_out, &context);
    
    LOG_DEBUG("Successfully extracted and hashed SubjectPublicKeyInfo (%zu bytes)", total_spki_length);
    return true;
}

static bool privacy_hostname_matches_pin(const char *hostname, const cert_pin_t *pin) {
    if (!hostname || !pin) return false;
    
    if (pin->wildcard_match) {
        // For wildcard matching, check if hostname ends with the pin hostname
        size_t hostname_len = strlen(hostname);
        size_t pin_len = strlen(pin->hostname);
        
        if (hostname_len >= pin_len) {
            const char *suffix = hostname + (hostname_len - pin_len);
            return strcasecmp(suffix, pin->hostname) == 0;
        }
        
        return false;
    } else {
        // Exact hostname match
        return strcasecmp(hostname, pin->hostname) == 0;
    }
}

// Intelligent IPv6 leak detection - determines if IPv6 traffic is legitimate
static bool privacy_guards_is_legitimate_ipv6_traffic(privacy_guards_t *guards, const flow_tuple_t *flow) {
    if (!guards || !flow) return false;
    
    // If VPN explicitly supports IPv6, allow IPv6 traffic through the tunnel
    if (guards->vpn_supports_ipv6 && guards->vpn_tunnel_active) {
        return true;
    }
    
    // If VPN is IPv4-only, we need to check if this IPv6 traffic is bypassing the VPN
    if (!guards->vpn_supports_ipv6) {
        // Check for link-local IPv6 traffic (fe80::/10) - this is legitimate local traffic
        if (flow->ip_version == 6 && flow->dst_ip.v6.addr[0] == 0xfe && 
            (flow->dst_ip.v6.addr[1] & 0xc0) == 0x80) {
            return true;
        }
        
        // Check for loopback IPv6 traffic (::1) - legitimate local traffic
        if (flow->ip_version == 6) {
            bool is_loopback = true;
            for (int i = 0; i < 15; i++) {
                if (flow->dst_ip.v6.addr[i] != 0) {
                    is_loopback = false;
                    break;
                }
            }
            if (is_loopback && flow->dst_ip.v6.addr[15] == 1) {
                return true;
            }
        }
        
        // Check for multicast IPv6 traffic (ff00::/8) - may be legitimate
        if (flow->ip_version == 6 && flow->dst_ip.v6.addr[0] == 0xff) {
            // Extract multicast scope from second byte (lower 4 bits)
            uint8_t scope = flow->dst_ip.v6.addr[1] & 0x0f;
            
            // Allow node-local (1) and link-local (2) multicast
            if (scope <= 2) {
                return true;
            } else {
                return false;
            }
        }
        
        // All other IPv6 traffic in IPv4-only VPN is a potential leak
        return false;
    }
    
    // If VPN tunnel is not active, any IPv6 traffic is potentially a leak
    if (!guards->vpn_tunnel_active) {
        return false;
    }
    
    // Default to allowing traffic if unsure
    return true;
}

// Configure privacy guards with VPN capabilities for proper leak detection
bool privacy_guards_set_vpn_config(privacy_guards_t *guards, bool supports_ipv4, bool supports_ipv6, bool tunnel_active) {
    if (!guards) return false;
    
    pthread_mutex_lock(&guards->mutex);
    
    guards->vpn_supports_ipv4 = supports_ipv4;
    guards->vpn_supports_ipv6 = supports_ipv6;
    guards->vpn_tunnel_active = tunnel_active;
    
    pthread_mutex_unlock(&guards->mutex);
    
    LOG_INFO("Privacy guards VPN config updated: IPv4=%s, IPv6=%s, tunnel_active=%s", 
             supports_ipv4 ? "enabled" : "disabled",
             supports_ipv6 ? "enabled" : "disabled", 
             tunnel_active ? "active" : "inactive");
    
    return true;
}

// Update tunnel status for privacy guards
bool privacy_guards_set_tunnel_status(privacy_guards_t *guards, bool tunnel_active) {
    if (!guards) return false;
    
    pthread_mutex_lock(&guards->mutex);
    guards->vpn_tunnel_active = tunnel_active;
    pthread_mutex_unlock(&guards->mutex);
    
    LOG_DEBUG("Privacy guards tunnel status updated: %s", tunnel_active ? "active" : "inactive");
    return true;
}