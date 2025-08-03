#include "reachability/monitor.h"
#include "core/logging.h"
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <sys/socket.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <unistd.h>

#ifdef TARGET_OS_IOS
#import <Foundation/Foundation.h>
#import <CoreTelephony/CTTelephonyNetworkInfo.h>
#import <CoreTelephony/CTCarrier.h>
#endif

#define REACHABILITY_DEFAULT_TRANSITION_DELAY 1000 // 1 second

struct reachability_monitor {
    network_status_t current_status;
    network_type_t current_type;
    network_status_t previous_status;
    network_type_t previous_type;
    
    reachability_callback_t callback;
    void *user_data;
    
    uint32_t transition_delay_ms;
    uint64_t last_transition_ns;
    bool monitoring_active;
    
    pthread_mutex_t mutex;
    pthread_t monitor_thread;
    bool thread_running;
    
#ifdef TARGET_OS_IOS
    SCNetworkReachabilityRef reachability_ref;
    nw_path_monitor_t path_monitor;
    dispatch_queue_t monitor_queue;
#endif
};

static void *reachability_monitor_thread(void *arg);
static network_status_t reachability_detect_status(reachability_monitor_t *monitor);
static network_type_t reachability_detect_type(reachability_monitor_t *monitor);
static void reachability_notify_change(reachability_monitor_t *monitor, network_status_t new_status, network_type_t new_type);

#ifdef TARGET_OS_IOS
static void reachability_callback_ios(SCNetworkReachabilityRef target, SCNetworkReachabilityFlags flags, void *info) {
    // Handle iOS reachability callback
    reachability_monitor_t *monitor = (reachability_monitor_t *)info;
    if (monitor) {
        reachability_monitor_force_update(monitor);
    }
}

static void path_update_handler(nw_path_t path) {
    // Handle network path updates
    nw_path_status_t status = nw_path_get_status(path);
    LOG_DEBUG("Network path status changed: %d", (int)status);
}
#endif

reachability_monitor_t *reachability_monitor_create(void) {
    reachability_monitor_t *monitor = calloc(1, sizeof(reachability_monitor_t));
    if (!monitor) {
        LOG_ERROR("Failed to allocate reachability monitor");
        return NULL;
    }
    
    if (pthread_mutex_init(&monitor->mutex, NULL) != 0) {
        LOG_ERROR("Failed to initialize reachability monitor mutex");
        free(monitor);
        return NULL;
    }
    
    monitor->current_status = NETWORK_STATUS_UNKNOWN;
    monitor->current_type = NETWORK_TYPE_UNKNOWN;
    monitor->previous_status = NETWORK_STATUS_UNKNOWN;
    monitor->previous_type = NETWORK_TYPE_UNKNOWN;
    monitor->transition_delay_ms = REACHABILITY_DEFAULT_TRANSITION_DELAY;
    monitor->monitoring_active = false;
    monitor->thread_running = false;
    
#ifdef TARGET_OS_IOS
    monitor->monitor_queue = dispatch_queue_create("com.relativevpn.reachability", DISPATCH_QUEUE_SERIAL);
    monitor->path_monitor = nw_path_monitor_create();
    
    if (monitor->path_monitor && monitor->monitor_queue) {
        nw_path_monitor_set_queue(monitor->path_monitor, monitor->monitor_queue);
        nw_path_monitor_set_update_handler(monitor->path_monitor, ^(nw_path_t path) {
            path_update_handler(path);
        });
    }
#endif
    
    LOG_INFO("Reachability monitor created");
    return monitor;
}

void reachability_monitor_destroy(reachability_monitor_t *monitor) {
    if (!monitor) return;
    
    reachability_monitor_stop(monitor);
    
    pthread_mutex_lock(&monitor->mutex);
    
#ifdef TARGET_OS_IOS
    if (monitor->path_monitor) {
        nw_path_monitor_cancel(monitor->path_monitor);
        monitor->path_monitor = nil;
    }
    
    if (monitor->reachability_ref) {
        SCNetworkReachabilityUnscheduleFromRunLoop(monitor->reachability_ref, 
                                                   CFRunLoopGetCurrent(), 
                                                   kCFRunLoopDefaultMode);
        CFRelease(monitor->reachability_ref);
        monitor->reachability_ref = NULL;
    }
    
    if (monitor->monitor_queue) {
        dispatch_release(monitor->monitor_queue);
        monitor->monitor_queue = NULL;
    }
#endif
    
    pthread_mutex_unlock(&monitor->mutex);
    pthread_mutex_destroy(&monitor->mutex);
    
    free(monitor);
    LOG_INFO("Reachability monitor destroyed");
}

bool reachability_monitor_start(reachability_monitor_t *monitor, reachability_callback_t callback, void *user_data) {
    if (!monitor) return false;
    
    pthread_mutex_lock(&monitor->mutex);
    
    if (monitor->monitoring_active) {
        LOG_WARN("Reachability monitor already active");
        pthread_mutex_unlock(&monitor->mutex);
        return false;
    }
    
    monitor->callback = callback;
    monitor->user_data = user_data;
    monitor->monitoring_active = true;
    monitor->thread_running = true;
    
    monitor->current_status = reachability_detect_status(monitor);
    monitor->current_type = reachability_detect_type(monitor);
    
    if (pthread_create(&monitor->monitor_thread, NULL, reachability_monitor_thread, monitor) != 0) {
        LOG_ERROR("Failed to create reachability monitor thread");
        monitor->monitoring_active = false;
        monitor->thread_running = false;
        pthread_mutex_unlock(&monitor->mutex);
        return false;
    }
    
#ifdef TARGET_OS_IOS
    if (monitor->path_monitor) {
        nw_path_monitor_start(monitor->path_monitor);
    }
#endif
    
    pthread_mutex_unlock(&monitor->mutex);
    
    LOG_INFO("Reachability monitor started");
    return true;
}

void reachability_monitor_stop(reachability_monitor_t *monitor) {
    if (!monitor) return;
    
    pthread_mutex_lock(&monitor->mutex);
    
    if (!monitor->monitoring_active) {
        pthread_mutex_unlock(&monitor->mutex);
        return;
    }
    
    monitor->monitoring_active = false;
    monitor->thread_running = false;
    
#ifdef TARGET_OS_IOS
    if (monitor->path_monitor) {
        nw_path_monitor_cancel(monitor->path_monitor);
    }
#endif
    
    pthread_mutex_unlock(&monitor->mutex);
    
    if (pthread_join(monitor->monitor_thread, NULL) != 0) {
        LOG_WARN("Failed to join reachability monitor thread");
    }
    
    LOG_INFO("Reachability monitor stopped");
}

network_status_t reachability_monitor_get_status(reachability_monitor_t *monitor) {
    if (!monitor) return NETWORK_STATUS_UNKNOWN;
    
    pthread_mutex_lock(&monitor->mutex);
    network_status_t status = monitor->current_status;
    pthread_mutex_unlock(&monitor->mutex);
    
    return status;
}

network_type_t reachability_monitor_get_network_type(reachability_monitor_t *monitor) {
    if (!monitor) return NETWORK_TYPE_UNKNOWN;
    
    pthread_mutex_lock(&monitor->mutex);
    network_type_t type = monitor->current_type;
    pthread_mutex_unlock(&monitor->mutex);
    
    return type;
}

bool reachability_monitor_is_connected(reachability_monitor_t *monitor) {
    network_status_t status = reachability_monitor_get_status(monitor);
    return status == NETWORK_STATUS_REACHABLE_VIA_WIFI ||
           status == NETWORK_STATUS_REACHABLE_VIA_CELLULAR ||
           status == NETWORK_STATUS_REACHABLE_VIA_ETHERNET;
}

bool reachability_monitor_should_pause_connections(reachability_monitor_t *monitor) {
    if (!monitor) return true;
    
    pthread_mutex_lock(&monitor->mutex);
    
    uint64_t current_time = clock_gettime_nsec_np(CLOCK_MONOTONIC);
    uint64_t delay_ns = monitor->transition_delay_ms * 1000000ULL;
    
    bool should_pause = (current_time - monitor->last_transition_ns) < delay_ns;
    
    pthread_mutex_unlock(&monitor->mutex);
    
    return should_pause;
}

bool reachability_monitor_get_interface_info(reachability_monitor_t *monitor, const char *interface_name, 
                                           network_interface_info_t *info) {
    if (!monitor || !interface_name || !info) return false;
    
    struct ifaddrs *ifaddrs_ptr = NULL;
    if (getifaddrs(&ifaddrs_ptr) != 0) {
        LOG_ERROR("Failed to get interface addresses");
        return false;
    }
    
    bool found = false;
    
    for (struct ifaddrs *ifa = ifaddrs_ptr; ifa != NULL; ifa = ifa->ifa_next) {
        if (strcmp(ifa->ifa_name, interface_name) == 0 && ifa->ifa_addr) {
            memset(info, 0, sizeof(network_interface_info_t));
            strncpy(info->name, interface_name, sizeof(info->name) - 1);
            
            if (ifa->ifa_addr->sa_family == AF_INET) {
                struct sockaddr_in *addr_in = (struct sockaddr_in *)ifa->ifa_addr;
                inet_ntop(AF_INET, &addr_in->sin_addr, info->ip_address, sizeof(info->ip_address));
                
                if (ifa->ifa_netmask) {
                    struct sockaddr_in *mask_in = (struct sockaddr_in *)ifa->ifa_netmask;
                    inet_ntop(AF_INET, &mask_in->sin_addr, info->subnet_mask, sizeof(info->subnet_mask));
                }
            } else if (ifa->ifa_addr->sa_family == AF_INET6) {
                struct sockaddr_in6 *addr_in6 = (struct sockaddr_in6 *)ifa->ifa_addr;
                inet_ntop(AF_INET6, &addr_in6->sin6_addr, info->ip_address, sizeof(info->ip_address));
                info->supports_ipv6 = true;
            }
            
            info->is_active = (ifa->ifa_flags & IFF_UP) && (ifa->ifa_flags & IFF_RUNNING);
            
            if (strncmp(interface_name, "en", 2) == 0) {
                info->type = NETWORK_TYPE_WIFI;
            } else if (strncmp(interface_name, "pdp_ip", 6) == 0) {
                info->type = NETWORK_TYPE_CELLULAR_4G;
            } else {
                info->type = NETWORK_TYPE_UNKNOWN;
            }
            
            found = true;
            break;
        }
    }
    
    freeifaddrs(ifaddrs_ptr);
    return found;
}

size_t reachability_monitor_get_all_interfaces(reachability_monitor_t *monitor, 
                                              network_interface_info_t *interfaces, size_t max_count) {
    if (!monitor || !interfaces || max_count == 0) return 0;
    
    struct ifaddrs *ifaddrs_ptr = NULL;
    if (getifaddrs(&ifaddrs_ptr) != 0) {
        LOG_ERROR("Failed to get interface addresses");
        return 0;
    }
    
    size_t count = 0;
    
    for (struct ifaddrs *ifa = ifaddrs_ptr; ifa != NULL && count < max_count; ifa = ifa->ifa_next) {
        if (ifa->ifa_addr && (ifa->ifa_addr->sa_family == AF_INET || ifa->ifa_addr->sa_family == AF_INET6)) {
            reachability_monitor_get_interface_info(monitor, ifa->ifa_name, &interfaces[count]);
            count++;
        }
    }
    
    freeifaddrs(ifaddrs_ptr);
    return count;
}

void reachability_monitor_force_update(reachability_monitor_t *monitor) {
    if (!monitor) return;
    
    network_status_t new_status = reachability_detect_status(monitor);
    network_type_t new_type = reachability_detect_type(monitor);
    
    pthread_mutex_lock(&monitor->mutex);
    
    if (new_status != monitor->current_status || new_type != monitor->current_type) {
        reachability_notify_change(monitor, new_status, new_type);
    }
    
    pthread_mutex_unlock(&monitor->mutex);
}

static void *reachability_monitor_thread(void *arg) {
    reachability_monitor_t *monitor = (reachability_monitor_t *)arg;
    
    LOG_DEBUG("Reachability monitor thread started");
    
    while (monitor->thread_running) {
        network_status_t new_status = reachability_detect_status(monitor);
        network_type_t new_type = reachability_detect_type(monitor);
        
        pthread_mutex_lock(&monitor->mutex);
        
        if (new_status != monitor->current_status || new_type != monitor->current_type) {
            reachability_notify_change(monitor, new_status, new_type);
        }
        
        pthread_mutex_unlock(&monitor->mutex);
        
        usleep(500000); // 500ms
    }
    
    LOG_DEBUG("Reachability monitor thread finished");
    return NULL;
}

static network_status_t reachability_detect_status(reachability_monitor_t *monitor) {
    struct ifaddrs *ifaddrs_ptr = NULL;
    if (getifaddrs(&ifaddrs_ptr) != 0) {
        return NETWORK_STATUS_NOT_REACHABLE;
    }
    
    network_status_t status = NETWORK_STATUS_NOT_REACHABLE;
    
    for (struct ifaddrs *ifa = ifaddrs_ptr; ifa != NULL; ifa = ifa->ifa_next) {
        if (ifa->ifa_flags & IFF_UP && ifa->ifa_flags & IFF_RUNNING && 
            !(ifa->ifa_flags & IFF_LOOPBACK)) {
            
            if (strncmp(ifa->ifa_name, "en", 2) == 0) {
                status = NETWORK_STATUS_REACHABLE_VIA_WIFI;
                break;
            } else if (strncmp(ifa->ifa_name, "pdp_ip", 6) == 0) {
                status = NETWORK_STATUS_REACHABLE_VIA_CELLULAR;
            }
        }
    }
    
    freeifaddrs(ifaddrs_ptr);
    return status;
}

static network_type_t reachability_detect_type(reachability_monitor_t *monitor) {
    network_status_t status = reachability_detect_status(monitor);
    
    switch (status) {
        case NETWORK_STATUS_REACHABLE_VIA_WIFI:
            return NETWORK_TYPE_WIFI;
        case NETWORK_STATUS_REACHABLE_VIA_CELLULAR:
#ifdef TARGET_OS_IOS
            // Try to detect cellular generation
            CTTelephonyNetworkInfo *networkInfo = [[CTTelephonyNetworkInfo alloc] init];
            if (networkInfo.serviceCurrentRadioAccessTechnology) {
                NSString *radioTech = [networkInfo.serviceCurrentRadioAccessTechnology.allValues firstObject];
                if ([radioTech isEqualToString:CTRadioAccessTechnologyNR] ||
                    [radioTech isEqualToString:CTRadioAccessTechnologyNRNSA]) {
                    return NETWORK_TYPE_CELLULAR_5G;
                } else if ([radioTech isEqualToString:CTRadioAccessTechnologyLTE]) {
                    return NETWORK_TYPE_CELLULAR_4G;
                } else if ([radioTech containsString:@"WCDMA"] || [radioTech containsString:@"HSDPA"]) {
                    return NETWORK_TYPE_CELLULAR_3G;
                } else {
                    return NETWORK_TYPE_CELLULAR_2G;
                }
            }
#endif
            return NETWORK_TYPE_CELLULAR_4G;
        case NETWORK_STATUS_REACHABLE_VIA_ETHERNET:
            return NETWORK_TYPE_ETHERNET;
        default:
            return NETWORK_TYPE_NONE;
    }
}

static void reachability_notify_change(reachability_monitor_t *monitor, network_status_t new_status, network_type_t new_type) {
    reachability_event_t event = {0};
    event.old_status = monitor->current_status;
    event.new_status = new_status;
    event.old_type = monitor->current_type;
    event.new_type = new_type;
    event.timestamp_ns = clock_gettime_nsec_np(CLOCK_MONOTONIC);
    event.connection_lost = (monitor->current_status != NETWORK_STATUS_NOT_REACHABLE && 
                           new_status == NETWORK_STATUS_NOT_REACHABLE);
    event.connection_gained = (monitor->current_status == NETWORK_STATUS_NOT_REACHABLE && 
                             new_status != NETWORK_STATUS_NOT_REACHABLE);
    event.type_changed = (monitor->current_type != new_type);
    
    monitor->previous_status = monitor->current_status;
    monitor->previous_type = monitor->current_type;
    monitor->current_status = new_status;
    monitor->current_type = new_type;
    monitor->last_transition_ns = event.timestamp_ns;
    
    if (monitor->callback) {
        monitor->callback(&event, monitor->user_data);
    }
    
    LOG_INFO("Network status changed: %s -> %s, Type: %s -> %s",
             reachability_network_status_string(event.old_status),
             reachability_network_status_string(event.new_status),
             reachability_network_type_string(event.old_type),
             reachability_network_type_string(event.new_type));
}

const char *reachability_network_type_string(network_type_t type) {
    switch (type) {
        case NETWORK_TYPE_UNKNOWN: return "Unknown";
        case NETWORK_TYPE_WIFI: return "WiFi";
        case NETWORK_TYPE_CELLULAR_2G: return "Cellular 2G";
        case NETWORK_TYPE_CELLULAR_3G: return "Cellular 3G";
        case NETWORK_TYPE_CELLULAR_4G: return "Cellular 4G";
        case NETWORK_TYPE_CELLULAR_5G: return "Cellular 5G";
        case NETWORK_TYPE_ETHERNET: return "Ethernet";
        case NETWORK_TYPE_NONE: return "None";
        default: return "Invalid";
    }
}

const char *reachability_network_status_string(network_status_t status) {
    switch (status) {
        case NETWORK_STATUS_UNKNOWN: return "Unknown";
        case NETWORK_STATUS_NOT_REACHABLE: return "Not Reachable";
        case NETWORK_STATUS_REACHABLE_VIA_WIFI: return "Reachable via WiFi";
        case NETWORK_STATUS_REACHABLE_VIA_CELLULAR: return "Reachable via Cellular";
        case NETWORK_STATUS_REACHABLE_VIA_ETHERNET: return "Reachable via Ethernet";
        default: return "Invalid";
    }
}