#ifndef RELATIVE_VPN_H
#define RELATIVE_VPN_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

// Forward declarations from core types
#include "core/types.h"

// VPN handle type
typedef void* vpn_handle_t;
#define VPN_INVALID_HANDLE ((vpn_handle_t)NULL)

// MTU constants are defined in core/types.h

#ifdef __cplusplus
extern "C" {
#endif

typedef struct vpn_config {
    char *utun_name;
    uint16_t mtu;
    uint16_t tunnel_mtu;
    bool ipv4_enabled;
    bool ipv6_enabled;
    bool enable_nat64;
    bool enable_dns_leak_protection;
    bool enable_ipv6_leak_protection;
    bool enable_kill_switch;
    bool enable_webrtc_leak_protection;
    uint32_t dns_cache_size;
    uint32_t metrics_buffer_size;
    bool reachability_monitoring;
    char *log_level;
    uint32_t dns_servers[8];  // MAX_DNS_SERVERS
    int dns_server_count;
} vpn_config_t;

typedef struct vpn_metrics {
    uint64_t bytes_in;
    uint64_t bytes_out;
    uint64_t bytes_received;
    uint64_t bytes_sent;
    uint64_t packets_in;
    uint64_t packets_out;
    uint32_t tcp_connections;
    uint32_t udp_sessions;
    uint32_t dns_queries;
    uint32_t dns_cache_hits;
    uint32_t dns_cache_misses;
    uint32_t packets_blocked;
    uint32_t privacy_violations;
    uint32_t dns_leaks_detected;
    uint32_t nat64_translations;
    uint32_t tcp_established_connections;
    uint32_t total_packets_processed;
    uint32_t packet_errors;
    uint32_t encrypted_packets;
    uint32_t network_status;
    uint32_t active_connections;
    uint32_t dns_cache_size;
    uint32_t dns_cache_max_size;
    float dns_cache_hit_rate;
    uint64_t uptime_seconds;
    uint64_t timestamp_ns;
} vpn_metrics_t;

typedef enum {
    VPN_SUCCESS = 0,
    VPN_ERROR_INVALID_CONFIG = -1,
    VPN_ERROR_UTUN_FAILED = -2,
    VPN_ERROR_ALREADY_RUNNING = -3,
    VPN_ERROR_NOT_RUNNING = -4,
    VPN_ERROR_MEMORY = -5,
    VPN_ERROR_NETWORK = -6,
    VPN_ERROR_PERMISSION = -7
} vpn_status_t;

typedef void (*vpn_metrics_callback_t)(const vpn_metrics_t *metrics, void *user_data);
typedef void (*vpn_log_callback_t)(const char *message, void *user_data);

// Simple VPN API
vpn_status_t vpn_start(const vpn_config_t *config);
vpn_status_t vpn_stop(void);
vpn_status_t vpn_inject(const uint8_t *packet, size_t length);
vpn_status_t vpn_get_metrics(vpn_metrics_t *metrics);
vpn_status_t vpn_set_metrics_callback(vpn_metrics_callback_t callback, void *user_data);
vpn_status_t vpn_set_log_callback(vpn_log_callback_t callback, void *user_data);
bool vpn_is_running(void);
const char *vpn_error_string(vpn_status_t result);

// Comprehensive VPN API with handle-based management
typedef struct vpn_result {
    int status;
    vpn_handle_t handle;
} vpn_result_t;

vpn_result_t vpn_start_comprehensive(const vpn_config_t *config);
bool vpn_stop_comprehensive(vpn_handle_t handle);
bool vpn_inject_packet_comprehensive(vpn_handle_t handle, const packet_info_t *packet);
bool vpn_get_metrics_comprehensive(vpn_handle_t handle, vpn_metrics_t *metrics);
bool vpn_is_running_comprehensive(vpn_handle_t handle);
bool vpn_update_config_comprehensive(vpn_handle_t handle, const vpn_config_t *config);
bool vpn_get_config_comprehensive(vpn_handle_t handle, vpn_config_t *config);

// Crash reporting functions (require crash/reporter.h for crash_stats_t)
struct crash_stats;
typedef struct crash_stats crash_stats_t;
bool vpn_get_crash_stats_comprehensive(vpn_handle_t handle, crash_stats_t *stats);
bool vpn_report_custom_error_comprehensive(vpn_handle_t handle, const char *error_description);

#ifdef __cplusplus
}
#endif

#endif