#ifndef RELATIVE_VPN_REACHABILITY_MONITOR_H
#define RELATIVE_VPN_REACHABILITY_MONITOR_H

#include "core/types.h"
#include <stdint.h>
#include <stdbool.h>

#ifdef TARGET_OS_IOS
#import <SystemConfiguration/SystemConfiguration.h>
#import <Network/Network.h>
#endif

typedef struct reachability_monitor reachability_monitor_t;

typedef enum network_type {
    NETWORK_TYPE_UNKNOWN = 0,
    NETWORK_TYPE_WIFI,
    NETWORK_TYPE_CELLULAR_2G,
    NETWORK_TYPE_CELLULAR_3G,
    NETWORK_TYPE_CELLULAR_4G,
    NETWORK_TYPE_CELLULAR_5G,
    NETWORK_TYPE_ETHERNET,
    NETWORK_TYPE_NONE
} network_type_t;

typedef enum network_status {
    NETWORK_STATUS_UNKNOWN = 0,
    NETWORK_STATUS_NOT_REACHABLE,
    NETWORK_STATUS_REACHABLE_VIA_WIFI,
    NETWORK_STATUS_REACHABLE_VIA_CELLULAR,
    NETWORK_STATUS_REACHABLE_VIA_ETHERNET
} network_status_t;

typedef struct network_interface_info {
    char name[16];
    char ip_address[46];
    char subnet_mask[46];
    char gateway[46];
    char dns_servers[256];
    network_type_t type;
    bool is_active;
    bool supports_ipv6;
    uint32_t mtu;
    uint64_t bytes_sent;
    uint64_t bytes_received;
} network_interface_info_t;

typedef struct reachability_event {
    network_status_t old_status;
    network_status_t new_status;
    network_type_t old_type;
    network_type_t new_type;
    uint64_t timestamp_ns;
    bool connection_lost;
    bool connection_gained;
    bool type_changed;
} reachability_event_t;

typedef void (*reachability_callback_t)(const reachability_event_t *event, void *user_data);

reachability_monitor_t *reachability_monitor_create(void);
void reachability_monitor_destroy(reachability_monitor_t *monitor);

bool reachability_monitor_start(reachability_monitor_t *monitor, reachability_callback_t callback, void *user_data);
void reachability_monitor_stop(reachability_monitor_t *monitor);

network_status_t reachability_monitor_get_status(reachability_monitor_t *monitor);
network_type_t reachability_monitor_get_network_type(reachability_monitor_t *monitor);
bool reachability_monitor_is_connected(reachability_monitor_t *monitor);

bool reachability_monitor_is_wifi_available(reachability_monitor_t *monitor);
bool reachability_monitor_is_cellular_available(reachability_monitor_t *monitor);
bool reachability_monitor_is_ethernet_available(reachability_monitor_t *monitor);

bool reachability_monitor_get_interface_info(reachability_monitor_t *monitor, const char *interface_name, 
                                           network_interface_info_t *info);
size_t reachability_monitor_get_all_interfaces(reachability_monitor_t *monitor, 
                                              network_interface_info_t *interfaces, size_t max_count);

void reachability_monitor_set_transition_delay(reachability_monitor_t *monitor, uint32_t delay_ms);
uint32_t reachability_monitor_get_transition_delay(reachability_monitor_t *monitor);

bool reachability_monitor_should_pause_connections(reachability_monitor_t *monitor);
void reachability_monitor_force_update(reachability_monitor_t *monitor);

const char *reachability_network_type_string(network_type_t type);
const char *reachability_network_status_string(network_status_t status);

#ifdef TARGET_OS_IOS
bool reachability_monitor_set_host_target(reachability_monitor_t *monitor, const char *hostname);
bool reachability_monitor_set_address_target(reachability_monitor_t *monitor, const struct sockaddr *address);
#endif

#endif