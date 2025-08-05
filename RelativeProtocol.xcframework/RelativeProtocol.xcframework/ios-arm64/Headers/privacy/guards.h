#ifndef RELATIVE_VPN_PRIVACY_GUARDS_H
#define RELATIVE_VPN_PRIVACY_GUARDS_H

#include "core/types.h"
#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct privacy_guards privacy_guards_t;

typedef enum dns_leak_status {
    DNS_LEAK_STATUS_NONE = 0,
    DNS_LEAK_STATUS_DETECTED,
    DNS_LEAK_STATUS_BLOCKED,
    DNS_LEAK_STATUS_KILL_SWITCH_ACTIVE
} dns_leak_status_t;

typedef enum privacy_violation_type {
    PRIVACY_VIOLATION_DNS_LEAK = 1,
    PRIVACY_VIOLATION_IPV6_LEAK = 2,
    PRIVACY_VIOLATION_WEBRTC_LEAK = 4,
    PRIVACY_VIOLATION_UNENCRYPTED_DNS = 8,
    PRIVACY_VIOLATION_WEAK_ENCRYPTION = 16
} privacy_violation_type_t;

typedef struct privacy_violation {
    privacy_violation_type_t type;
    ip_addr_t source_addr;
    ip_addr_t destination_addr;
    uint16_t source_port;
    uint16_t destination_port;
    uint8_t protocol;
    char description[256];
    uint64_t timestamp_ns;
    bool blocked;
} privacy_violation_t;

typedef struct privacy_stats {
    uint32_t total_violations;
    uint32_t dns_leaks_detected;
    uint32_t dns_leaks_blocked;
    uint32_t ipv6_leaks_detected;
    uint32_t ipv6_leaks_blocked;
    uint32_t webrtc_leaks_detected;
    uint32_t webrtc_leaks_blocked;
    uint32_t unencrypted_dns_queries;
    uint32_t weak_encryption_detected;
    uint32_t packets_inspected;
    uint32_t packets_blocked;
    uint64_t kill_switch_activations;
    uint32_t certificate_pins_validated;
    uint32_t certificate_pin_failures;
    uint32_t certificate_validation_failures;
} privacy_stats_t;

typedef void (*privacy_violation_callback_t)(const privacy_violation_t *violation, void *user_data);

privacy_guards_t *privacy_guards_create(void);
void privacy_guards_destroy(privacy_guards_t *guards);

bool privacy_guards_enable_dns_leak_protection(privacy_guards_t *guards, bool enable);
bool privacy_guards_enable_ipv6_leak_protection(privacy_guards_t *guards, bool enable);
bool privacy_guards_enable_webrtc_leak_protection(privacy_guards_t *guards, bool enable);
bool privacy_guards_enable_kill_switch(privacy_guards_t *guards, bool enable);

bool privacy_guards_is_dns_leak_protection_enabled(privacy_guards_t *guards);
bool privacy_guards_is_ipv6_leak_protection_enabled(privacy_guards_t *guards);
bool privacy_guards_is_webrtc_leak_protection_enabled(privacy_guards_t *guards);
bool privacy_guards_is_kill_switch_enabled(privacy_guards_t *guards);

bool privacy_guards_set_allowed_dns_servers(privacy_guards_t *guards, const ip_addr_t *servers, size_t count);
bool privacy_guards_add_allowed_dns_server(privacy_guards_t *guards, const ip_addr_t *server);
bool privacy_guards_remove_allowed_dns_server(privacy_guards_t *guards, const ip_addr_t *server);

bool privacy_guards_inspect_packet(privacy_guards_t *guards, const uint8_t *packet, size_t length,
                                 const flow_tuple_t *flow, bool *should_block);

dns_leak_status_t privacy_guards_get_dns_leak_status(privacy_guards_t *guards);
bool privacy_guards_is_kill_switch_active(privacy_guards_t *guards);

void privacy_guards_set_violation_callback(privacy_guards_t *guards, privacy_violation_callback_t callback, void *user_data);

void privacy_guards_clear_memory(void *ptr, size_t size);
void privacy_guards_secure_zero(void *ptr, size_t size);

bool privacy_guards_validate_tls_connection(privacy_guards_t *guards, const uint8_t *tls_data, size_t length);
bool privacy_guards_check_certificate_pinning(privacy_guards_t *guards, const char *hostname, 
                                             const uint8_t *cert_data, size_t cert_length);

void privacy_guards_get_stats(privacy_guards_t *guards, privacy_stats_t *stats);
void privacy_guards_reset_stats(privacy_guards_t *guards);

const char *privacy_violation_type_string(privacy_violation_type_t type);
const char *dns_leak_status_string(dns_leak_status_t status);

bool privacy_guards_export_violations(privacy_guards_t *guards, privacy_violation_t *violations, 
                                     size_t max_count, size_t *actual_count);

// VPN configuration functions for proper IPv6 leak detection
bool privacy_guards_set_vpn_config(privacy_guards_t *guards, bool supports_ipv4, bool supports_ipv6, bool tunnel_active);
bool privacy_guards_set_tunnel_status(privacy_guards_t *guards, bool tunnel_active);

#if ENABLE_LOGGING == 0
#define privacy_guards_log_redacted(format, ...) do { } while(0)
#else
#define privacy_guards_log_redacted(format, ...) LOG_DEBUG("[REDACTED] " format, ##__VA_ARGS__)
#endif

#ifdef __cplusplus
}
#endif

#endif