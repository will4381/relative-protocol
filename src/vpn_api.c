/**
 * VPN API Implementation
 * Provides simple API functions for controlling VPN logging and basic functionality
 */

#include "api/relative_vpn.h"
#include "core/logging.h"
#include <string.h>
#include <stdio.h>
#include <arpa/inet.h>

// Simple VPN state tracking
static bool vpn_initialized = false;
static vpn_config_t current_config = {0};

vpn_status_t vpn_set_log_level(const char *level) {
    if (!level) {
        LOG_ERROR("Log level string is NULL");
        return VPN_ERROR_INVALID_CONFIG;
    }
    
    log_level_t new_level = log_level_from_string(level);
    log_set_level(new_level);
    
    LOG_INFO("Log level set to %s (%d)", level, new_level);
    return VPN_SUCCESS;
}

vpn_status_t vpn_get_log_level(char *level, size_t level_size) {
    if (!level || level_size == 0) {
        return VPN_ERROR_INVALID_CONFIG;
    }
    
    log_level_t current_level = log_get_level();
    const char* level_str = log_level_to_string(current_level);
    
    if (strlen(level_str) >= level_size) {
        return VPN_ERROR_MEMORY;
    }
    
    strncpy(level, level_str, level_size - 1);
    level[level_size - 1] = '\0';
    
    return VPN_SUCCESS;
}

vpn_status_t vpn_start(const vpn_config_t *config) {
    LOG_INFO("Starting VPN with configuration");
    
    if (!config) {
        LOG_ERROR("VPN config is NULL");
        return VPN_ERROR_INVALID_CONFIG;
    }
    
    if (vpn_initialized) {
        LOG_WARN("VPN already running");
        return VPN_ERROR_ALREADY_RUNNING;
    }
    
    // Initialize logging if a log level is specified
    if (config->log_level) {
        log_level_t level = log_level_from_string(config->log_level);
        log_init(level);
        LOG_INFO("Initialized logging at level: %s", config->log_level);
    }
    
    // Store current config
    current_config = *config;
    vpn_initialized = true;
    
    LOG_INFO("VPN started successfully - MTU: %d, IPv4: %s, IPv6: %s, NAT64: %s",
             config->mtu,
             config->ipv4_enabled ? "enabled" : "disabled",
             config->ipv6_enabled ? "enabled" : "disabled", 
             config->enable_nat64 ? "enabled" : "disabled");
    
    return VPN_SUCCESS;
}

vpn_status_t vpn_stop(void) {
    LOG_INFO("Stopping VPN");
    
    if (!vpn_initialized) {
        LOG_WARN("VPN not running");
        return VPN_ERROR_NOT_RUNNING;
    }
    
    vpn_initialized = false;
    memset(&current_config, 0, sizeof(current_config));
    
    LOG_INFO("VPN stopped successfully");
    return VPN_SUCCESS;
}

vpn_status_t vpn_inject(const uint8_t *packet, size_t length) {
    LOG_TRACE("Injecting packet: length=%zu", length);
    
    if (!vpn_initialized) {
        LOG_ERROR("VPN not running - cannot inject packet");
        return VPN_ERROR_NOT_RUNNING;
    }
    
    if (!packet || length == 0) {
        LOG_ERROR("Invalid packet parameters: packet=%p, length=%zu", packet, length);
        return VPN_ERROR_INVALID_CONFIG;
    }
    
    if (length > MAX_PACKET_SIZE) {
        LOG_ERROR("Packet too large: %zu bytes (max %d)", length, MAX_PACKET_SIZE);
        return VPN_ERROR_INVALID_CONFIG;
    }
    
    // Parse basic packet info for logging
    if (length >= 20) {
        uint8_t version = (packet[0] >> 4) & 0x0F;
        if (version == 4 && length >= 20) {
            uint8_t protocol = packet[9];
            uint32_t src_ip, dst_ip;
            memcpy(&src_ip, &packet[12], 4);
            memcpy(&dst_ip, &packet[16], 4);
            
            struct in_addr src_addr = {.s_addr = src_ip};
            struct in_addr dst_addr = {.s_addr = dst_ip};
            
            const char* protocol_name = "Unknown";
            if (protocol == 6) protocol_name = "TCP";
            else if (protocol == 17) protocol_name = "UDP";
            else if (protocol == 1) protocol_name = "ICMP";
            
            LOG_DEBUG("Injected IPv4 packet: %s -> %s (%s, %zu bytes)",
                      inet_ntoa(src_addr), inet_ntoa(dst_addr), protocol_name, length);
        } else if (version == 6) {
            LOG_DEBUG("Injected IPv6 packet: %zu bytes", length);
        } else {
            LOG_WARN("Injected packet with unknown IP version: %d", version);
        }
    }
    
    return VPN_SUCCESS;
}

vpn_status_t vpn_get_metrics(vpn_metrics_t *metrics) {
    if (!metrics) {
        return VPN_ERROR_INVALID_CONFIG;
    }
    
    if (!vpn_initialized) {
        return VPN_ERROR_NOT_RUNNING;
    }
    
    // Clear metrics structure
    memset(metrics, 0, sizeof(vpn_metrics_t));
    
    // This would be populated with real metrics in a full implementation
    LOG_TRACE("Retrieved VPN metrics");
    
    return VPN_SUCCESS;
}

vpn_status_t vpn_set_metrics_callback(vpn_metrics_callback_t callback, void *user_data) {
    LOG_INFO("Set metrics callback: %p (user_data: %p)", callback, user_data);
    return VPN_SUCCESS;
}

vpn_status_t vpn_set_log_callback(vpn_log_callback_t callback, void *user_data) {
    LOG_INFO("Set log callback: %p (user_data: %p)", callback, user_data);
    log_set_callback(callback, user_data);
    return VPN_SUCCESS;
}

bool vpn_is_running(void) {
    return vpn_initialized;
}

const char *vpn_error_string(vpn_status_t result) {
    switch (result) {
        case VPN_SUCCESS: return "Success";
        case VPN_ERROR_INVALID_CONFIG: return "Invalid configuration";
        case VPN_ERROR_UTUN_FAILED: return "Utun creation failed";
        case VPN_ERROR_ALREADY_RUNNING: return "VPN already running";
        case VPN_ERROR_NOT_RUNNING: return "VPN not running";
        case VPN_ERROR_MEMORY: return "Memory allocation error";
        case VPN_ERROR_NETWORK: return "Network error";
        case VPN_ERROR_PERMISSION: return "Permission error";
        default: return "Unknown error";
    }
}