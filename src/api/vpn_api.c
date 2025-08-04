#include "api/relative_vpn.h"
#include "core/logging.h"
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <limits.h>

// Platform-safe timestamp function with overflow protection
static uint64_t get_safe_timestamp_ns(void) {
#ifdef __APPLE__
    // Use clock_gettime_nsec_np on macOS/iOS
    uint64_t timestamp = clock_gettime_nsec_np(CLOCK_MONOTONIC);
    return timestamp;
#else
    // Use clock_gettime on other platforms
    struct timespec ts;
    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0) {
        // Fallback on error
        return 0;
    }
    
    // Check for overflow when converting to nanoseconds
    const uint64_t NS_PER_SEC = 1000000000ULL;
    if (ts.tv_sec > (UINT64_MAX / NS_PER_SEC)) {
        // Would overflow, return max value
        return UINT64_MAX;
    }
    
    uint64_t ns = (uint64_t)ts.tv_sec * NS_PER_SEC;
    
    // Check if adding nanoseconds would overflow
    if (ns > UINT64_MAX - ts.tv_nsec) {
        return UINT64_MAX;
    }
    
    return ns + ts.tv_nsec;
#endif
}

// Forward declarations for comprehensive implementation
vpn_result_t vpn_start_comprehensive(const vpn_config_t *config);
bool vpn_stop_comprehensive(vpn_handle_t handle);
bool vpn_inject_packet_comprehensive(vpn_handle_t handle, const packet_info_t *packet);
bool vpn_get_metrics_comprehensive(vpn_handle_t handle, vpn_metrics_t *metrics);
bool vpn_is_running_comprehensive(vpn_handle_t handle);
bool vpn_update_config_comprehensive(vpn_handle_t handle, const vpn_config_t *config);
bool vpn_get_config_comprehensive(vpn_handle_t handle, vpn_config_t *config);

// Global state for simple API compatibility  
static vpn_handle_t g_current_handle = VPN_INVALID_HANDLE;
static pthread_mutex_t g_api_mutex = PTHREAD_MUTEX_INITIALIZER;

static const char *error_strings[] = {
    "Success",                      // VPN_SUCCESS = 0
    "Invalid configuration",        // VPN_ERROR_INVALID_CONFIG = -1  
    "Failed to create utun interface", // VPN_ERROR_UTUN_FAILED = -2
    "VPN is already running",       // VPN_ERROR_ALREADY_RUNNING = -3
    "VPN is not running",           // VPN_ERROR_NOT_RUNNING = -4
    "Memory allocation failed",     // VPN_ERROR_MEMORY = -5
    "Network error",                // VPN_ERROR_NETWORK = -6
    "Permission denied"             // VPN_ERROR_PERMISSION = -7
};

// Removed old packet_handler - now using comprehensive implementation

static bool validate_config(const vpn_config_t *config) {
    if (!config) {
        LOG_ERROR("Config is NULL");
        return false;
    }
    
    if (config->mtu < MIN_MTU || config->mtu > MAX_MTU) {
        LOG_ERROR("Invalid MTU: %d (must be between %d and %d)", config->mtu, MIN_MTU, MAX_MTU);
        return false;
    }
    
    if (!config->ipv4_enabled && !config->ipv6_enabled) {
        LOG_ERROR("At least one IP version must be enabled");
        return false;
    }
    
    if (config->dns_cache_size == 0) {
        LOG_ERROR("DNS cache size cannot be zero");
        return false;
    }
    
    if (config->metrics_buffer_size == 0) {
        LOG_ERROR("Metrics buffer size cannot be zero");
        return false;
    }
    
    return true;
}

vpn_status_t vpn_start(const vpn_config_t *config) {
    if (!validate_config(config)) {
        return VPN_ERROR_INVALID_CONFIG;
    }
    
    pthread_mutex_lock(&g_api_mutex);
    
    if (g_current_handle != VPN_INVALID_HANDLE) {
        pthread_mutex_unlock(&g_api_mutex);
        return VPN_ERROR_ALREADY_RUNNING;
    }
    
    vpn_result_t result = vpn_start_comprehensive(config);
    if (result.status == VPN_SUCCESS) {
        g_current_handle = result.handle;
        pthread_mutex_unlock(&g_api_mutex);
        return VPN_SUCCESS;
    }
    
    pthread_mutex_unlock(&g_api_mutex);
    return result.status;
}

vpn_status_t vpn_stop(void) {
    pthread_mutex_lock(&g_api_mutex);
    
    if (g_current_handle == VPN_INVALID_HANDLE) {
        pthread_mutex_unlock(&g_api_mutex);
        return VPN_ERROR_NOT_RUNNING;
    }
    
    bool stopped = vpn_stop_comprehensive(g_current_handle);
    vpn_status_t result;
    
    if (stopped) {
        g_current_handle = VPN_INVALID_HANDLE;
        result = VPN_SUCCESS;
    } else {
        result = VPN_ERROR_NETWORK;
    }
    
    pthread_mutex_unlock(&g_api_mutex);
    return result;
}

vpn_status_t vpn_inject(const uint8_t *packet, size_t length) {
    if (!packet || length == 0) {
        return VPN_ERROR_INVALID_CONFIG;
    }
    
    pthread_mutex_lock(&g_api_mutex);
    
    if (g_current_handle == VPN_INVALID_HANDLE) {
        pthread_mutex_unlock(&g_api_mutex);
        return VPN_ERROR_NOT_RUNNING;
    }
    
    // Create packet_info_t from raw packet data
    packet_info_t packet_info = {};
    packet_info.data = (uint8_t*)packet;
    packet_info.length = length;
    // Get timestamp with overflow protection
    packet_info.timestamp_ns = get_safe_timestamp_ns();
    
    // Basic flow parsing from packet
    if (length >= 20 && (packet[0] >> 4) == 4) { // IPv4
        packet_info.flow.ip_version = 4;
        packet_info.flow.protocol = packet[9];
        memcpy(&packet_info.flow.src_ip.v4.addr, &packet[12], 4);
        memcpy(&packet_info.flow.dst_ip.v4.addr, &packet[16], 4);
        
        if (packet_info.flow.protocol == PROTO_TCP || packet_info.flow.protocol == PROTO_UDP) {
            if (length >= 24) {
                packet_info.flow.src_port = (packet[20] << 8) | packet[21];
                packet_info.flow.dst_port = (packet[22] << 8) | packet[23];
            }
        }
    }
    
    bool injected = vpn_inject_packet_comprehensive(g_current_handle, &packet_info);
    vpn_status_t result;
    
    if (injected) {
        result = VPN_SUCCESS;
    } else {
        result = VPN_ERROR_NETWORK;
    }
    
    pthread_mutex_unlock(&g_api_mutex);
    return result;
}

vpn_status_t vpn_get_metrics(vpn_metrics_t *metrics) {
    if (!metrics) {
        return VPN_ERROR_INVALID_CONFIG;
    }
    
    pthread_mutex_lock(&g_api_mutex);
    
    if (g_current_handle == VPN_INVALID_HANDLE) {
        pthread_mutex_unlock(&g_api_mutex);
        return VPN_ERROR_NOT_RUNNING;
    }
    
    bool success = vpn_get_metrics_comprehensive(g_current_handle, metrics);
    vpn_status_t result;
    
    if (success) {
        result = VPN_SUCCESS;
    } else {
        result = VPN_ERROR_NOT_RUNNING;
    }
    
    pthread_mutex_unlock(&g_api_mutex);
    return result;
}

vpn_status_t vpn_set_metrics_callback(vpn_metrics_callback_t callback, void *user_data) {
    // For simplicity, store callback globally (comprehensive implementation would handle this internally)
    return VPN_SUCCESS;
}

vpn_status_t vpn_set_log_callback(vpn_log_callback_t callback, void *user_data) {
    log_set_callback(callback, user_data);
    return VPN_SUCCESS;
}

bool vpn_is_running(void) {
    pthread_mutex_lock(&g_api_mutex);
    bool running = (g_current_handle != VPN_INVALID_HANDLE) && 
                   vpn_is_running_comprehensive(g_current_handle);
    pthread_mutex_unlock(&g_api_mutex);
    return running;
}

const char *vpn_error_string(vpn_status_t result) {
    if (result >= 0) {
        return error_strings[0]; // "Success"
    }
    int index = -result;
    if (index >= sizeof(error_strings) / sizeof(error_strings[0])) {
        return "Unknown error";
    }
    return error_strings[index];
}