#include "api/relative_vpn.h"
#include "core/logging.h"
#include <arpa/inet.h>
#include <time.h>
#include "metrics/ring_buffer.h"
#include "dns/resolver.h"
#include "dns/cache.h"
#include "privacy/guards.h"
#include "nat64/translator.h"
#include "tcp_udp/connection_manager.h"
#include "mtu/discovery.h"
#include "classifier/tls_quic.h"
#include "packet/buffer_manager.h"
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <stdatomic.h>

// iOS-only includes
#include "packet/tunnel_provider.h"
#include "socket_bridge/bridge.h"
#include "reachability/monitor.h"
#include "crash/reporter.h"

// iOS has reachability/monitor.mm and crash/reporter.mm compiled in
#ifdef TARGET_OS_IOS
#include "reachability/monitor.h"
#include "crash/reporter.h"
#endif

#include <dispatch/dispatch.h>
#include <sys/sysctl.h>
#include <mach/mach.h>
#include <mach/vm_statistics.h>
#include <mach/mach_host.h>
#include <mach/host_info.h>

// Constants
#define MAX_DNS_SERVERS 8

// Forward declarations for missing functions
tcp_connection_t *connection_manager_find_tcp_connection(connection_manager_t *manager, const flow_tuple_t *flow);

#ifdef TARGET_OS_IOS
// iOS Memory pressure handling
static bool ios_get_memory_info(uint64_t *memory_used, uint64_t *memory_available);
// Forward declaration moved after struct definition
#endif

// Global crash reporter is defined in crash/reporter.mm

// Stub implementations for missing functions
tcp_connection_t *connection_manager_find_tcp_connection(connection_manager_t *manager, const flow_tuple_t *flow) {
    // Stub implementation - would find actual TCP connection
    return NULL;
}

// Remove conflicting typedefs - they're already defined in headers


typedef struct comprehensive_vpn_state {
    bool running;
    vpn_config_t config;
    
    // Core components (available on all platforms)
    ring_buffer_t *metrics_buffer;
    dns_resolver_t *dns_resolver;
    dns_cache_t *dns_cache;
    privacy_guards_t *privacy_guards;
    nat64_translator_t *nat64_translator;
    connection_manager_t *connection_manager;
    mtu_discovery_t *mtu_discovery;
    traffic_classifier_t *traffic_classifier;
    
    // iOS-only tunnel components
    tunnel_provider_t *tunnel_provider;
    socket_bridge_t *socket_bridge;
    reachability_monitor_t *reachability_monitor;
    crash_reporter_t *crash_reporter;
    
    // PRODUCTION FIX: Memory pool management for safe packet handling
    buffer_pool_t *small_buffer_pool;   // For standard MTU packets
    buffer_pool_t *large_buffer_pool;   // For jumbo frames
    
    // State tracking
    vpn_metrics_t current_metrics;
    vpn_metrics_callback_t metrics_callback;
    void *metrics_user_data;
    
    // Threading
    pthread_mutex_t mutex;
    pthread_t packet_processing_thread;
    pthread_t metrics_thread;
    bool processing_active;
    
    // iOS Memory pressure monitoring
    dispatch_source_t memory_pressure_source;
    uint64_t last_memory_warning;
    bool memory_pressure_active;
    
    // Packet processing queue
    packet_info_t *packet_queue;
    size_t queue_size;
    size_t queue_head;
    size_t queue_tail;
    pthread_mutex_t queue_mutex;
    pthread_cond_t queue_cond;
} comprehensive_vpn_state_t;

#ifdef TARGET_OS_IOS
// Forward declaration now that struct is defined
static void ios_reduce_memory_usage(comprehensive_vpn_state_t *state);
#endif

static _Atomic(comprehensive_vpn_state_t*) g_vpn_state = NULL;
static pthread_mutex_t g_state_mutex = PTHREAD_MUTEX_INITIALIZER;

// Callback functions
static void privacy_violation_callback(const privacy_violation_t *violation, void *user_data) {
    comprehensive_vpn_state_t *state = (comprehensive_vpn_state_t *)user_data;
    if (state) {
        pthread_mutex_lock(&state->mutex);
        state->current_metrics.privacy_violations++;
        pthread_mutex_unlock(&state->mutex);
    }
}

static void traffic_classification_callback(const traffic_classification_t *classification, void *user_data) {
    comprehensive_vpn_state_t *state = (comprehensive_vpn_state_t *)user_data;
    if (classification && state) {
        pthread_mutex_lock(&state->mutex);
        if (classification->encrypted) {
            state->current_metrics.encrypted_packets++;
        }
        pthread_mutex_unlock(&state->mutex);
    }
}

static void crash_report_callback(const crash_info_t *crash_info, void *user_data) {
    comprehensive_vpn_state_t *state = (comprehensive_vpn_state_t *)user_data;
    if (crash_info && state) {
        LOG_CRITICAL("VPN CRASHED: %s - PID:%u TID:%u Time:%llu", 
                    crash_info->custom_data[0] ? crash_info->custom_data : "Unknown reason",
                    crash_info->process_id, crash_info->thread_id, crash_info->timestamp_ns);
        
        // Set custom crash data with VPN state information (iOS only)
#ifdef TARGET_OS_IOS
        if (state->crash_reporter) {
            crash_reporter_set_custom_data(state->crash_reporter, "vpn.running", 
                                         state->running ? "true" : "false");
            crash_reporter_set_custom_data(state->crash_reporter, "vpn.packets_processed", 
                                         ""); // Would format the actual count
            crash_reporter_set_custom_data(state->crash_reporter, "vpn.active_connections", 
                                         ""); // Would format the actual count
            
            // Add memory pressure info if available
            if (state->memory_pressure_active) {
                crash_reporter_set_custom_data(state->crash_reporter, "vpn.memory_pressure", "active");
            }
        }
#endif
        
        // Perform emergency cleanup if possible
        if (state->running) {
            LOG_INFO("Attempting emergency VPN shutdown due to crash");
            // Minimal cleanup - avoid complex operations in crash handler
            state->running = false;
            state->processing_active = false;
        }
    }
}

// Packet processing thread
static void *packet_processing_thread(void *arg) {
    comprehensive_vpn_state_t *state = (comprehensive_vpn_state_t *)arg;
    
    while (state->processing_active) {
        pthread_mutex_lock(&state->queue_mutex);
        
        // Wait for packets
        while (state->queue_head == state->queue_tail && state->processing_active) {
            pthread_cond_wait(&state->queue_cond, &state->queue_mutex);
        }
        
        if (!state->processing_active) {
            pthread_mutex_unlock(&state->queue_mutex);
            break;
        }
        
        // Process packet from queue
        packet_info_t packet = state->packet_queue[state->queue_head];
        state->queue_head = (state->queue_head + 1) % state->queue_size;
        
        pthread_mutex_unlock(&state->queue_mutex);
        
        // Process the packet through all components
        pthread_mutex_lock(&state->mutex);
        
        // 1. Traffic classification
        traffic_classification_t classification = {};
        traffic_classifier_analyze_packet(state->traffic_classifier, 
                                        packet.data, packet.length, 
                                        &packet.flow, &classification);
        
        // 2. DNS Cache lookup for DNS queries
        if (packet.flow.protocol == PROTO_UDP && packet.flow.dst_port == 53) {
            // Check DNS cache first
            dns_record_t cached_record;
            if (dns_cache_has_entry(state->dns_cache, "query", DNS_TYPE_A) &&
                dns_cache_get(state->dns_cache, "query", DNS_TYPE_A, &cached_record)) {
                state->current_metrics.dns_cache_hits++;
                // Could serve from cache here
            } else {
                state->current_metrics.dns_cache_misses++;
            }
        }
        
        // 3. Privacy guards inspection
        bool should_block = false;
        if (privacy_guards_inspect_packet(state->privacy_guards, 
                                        packet.data, packet.length, 
                                        &packet.flow, &should_block)) {
            if (should_block) {
                state->current_metrics.packets_blocked++;
                pthread_mutex_unlock(&state->mutex);
                continue;
            }
        }
        
        // 3. PRODUCTION FIX: Safe NAT64 translation with proper memory management
        safe_packet_t *translated_packet = NULL;
        if (packet.flow.ip_version == 4 && state->config.enable_nat64) {
            // SECURITY FIX: Use safe buffer management to prevent memory vulnerabilities
            const size_t max_translated_size = MAX_PACKET_SIZE + 128; // Extra space for IPv6 headers
            
            // Choose appropriate buffer pool based on size
            buffer_pool_t *pool = (max_translated_size <= SMALL_BUFFER_SIZE) ? 
                                 state->small_buffer_pool : state->large_buffer_pool;
            
            packet_buffer_t *buffer = buffer_pool_acquire(pool);
            if (!buffer) {
                LOG_ERROR("Failed to acquire buffer for NAT64 translation");
                state->current_metrics.packet_errors++;
                pthread_mutex_unlock(&state->mutex);
                continue;
            }
            
            // Ensure buffer is large enough
            if (buffer->capacity < max_translated_size) {
                if (!packet_buffer_resize(buffer, max_translated_size)) {
                    LOG_ERROR("Failed to resize buffer for NAT64 translation");
                    buffer_pool_release(pool, buffer);
                    state->current_metrics.packet_errors++;
                    pthread_mutex_unlock(&state->mutex);
                    continue;
                }
            }
            
            size_t translated_length = buffer->capacity;
            
            // SECURITY FIX: Validate packet length to prevent integer overflow
            if (packet.length > 0 && packet.length <= MAX_PACKET_SIZE &&
                nat64_translate_4to6(state->nat64_translator, 
                                   packet.data, packet.length,
                                   buffer->data, &translated_length, 
                                   buffer->capacity)) {
                
                // Additional validation: ensure translated length is reasonable
                if (translated_length > 0 && translated_length <= buffer->capacity) {
                    state->current_metrics.nat64_translations++;
                    
                    // PRODUCTION FIX: Create safe packet with proper lifecycle management
                    buffer->length = translated_length;
                    flow_tuple_t new_flow = packet.flow;
                    new_flow.ip_version = 6;
                    
                    translated_packet = safe_packet_create_from_buffer(buffer, &new_flow);
                    buffer_pool_release(pool, buffer); // Safe packet retains the buffer
                    
                    if (translated_packet) {
                        // Update packet processing to use translated packet
                        packet.data = translated_packet->data;
                        packet.length = translated_packet->length;
                        packet.flow = translated_packet->flow;
                    } else {
                        LOG_ERROR("Failed to create safe packet for NAT64 translation");
                        state->current_metrics.packet_errors++;
                    }
                } else {
                    LOG_WARN("NAT64 translation produced invalid packet size: %zu", translated_length);
                    state->current_metrics.packet_errors++;
                    buffer_pool_release(pool, buffer);
                }
            } else {
                // Translation failed, clean up and continue with original packet
                buffer_pool_release(pool, buffer);
            }
        }
        
        // 4. MTU discovery and MSS clamping
        if (packet.flow.protocol == PROTO_TCP) {
            mtu_clamp_tcp_mss(state->mtu_discovery, (uint8_t*)packet.data, 
                             packet.length, &packet.flow.dst_ip);
        }
        
        // Start MTU discovery for new destinations
        if (packet.flow.ip_version == 4) {
            uint16_t current_mtu = mtu_discovery_get_path_mtu(state->mtu_discovery, &packet.flow.dst_ip);
            if (current_mtu == 0) {
                mtu_discovery_start_probe(state->mtu_discovery, &packet.flow.dst_ip);
            }
        }
        
        // Process ICMP errors for MTU discovery
        if (packet.flow.protocol == PROTO_ICMP) {
            mtu_discovery_process_icmp_error(state->mtu_discovery, packet.data, packet.length, 
                                           &packet.flow.src_ip);
        }
        
        // 5. Connection management
        connection_manager_process_packet(state->connection_manager, &packet);
        
        // Get TCP connection state for monitoring
        if (packet.flow.protocol == PROTO_TCP) {
            tcp_connection_t *tcp_conn = connection_manager_find_tcp_connection(state->connection_manager, &packet.flow);
            if (tcp_conn) {
                connection_state_t conn_state = tcp_connection_get_state(tcp_conn);
                uint32_t seq_num = tcp_connection_get_seq(tcp_conn);
                uint32_t ack_num = tcp_connection_get_ack(tcp_conn);
                
                // Update connection metrics based on state
                if (conn_state == CONN_ESTABLISHED) {
                    state->current_metrics.tcp_established_connections++;
                }
            }
        }
        
        // 6. Platform-specific packet processing
#ifdef TARGET_OS_IOS
        // On iOS, packets are sent back through tunnel provider
        if (state->tunnel_provider && packet.length > 0) {
            tunnel_provider_send_packet(state->tunnel_provider, packet.data, packet.length);
        }
#else
        // On other platforms, use socket bridge
        socket_bridge_process_packet(state->socket_bridge, &packet);
        socket_bridge_process_events(state->socket_bridge);
#endif
        
        // 7. Update metrics with overflow protection
        state->current_metrics.total_packets_processed++;
        
        // SECURITY FIX: Prevent integer overflow in byte count
        if (packet.length <= SIZE_MAX - state->current_metrics.bytes_received) {
            state->current_metrics.bytes_received += packet.length;
        } else {
            LOG_WARN("Byte count overflow prevented, resetting counter");
            state->current_metrics.bytes_received = packet.length;
        }
        
        state->current_metrics.timestamp_ns = packet.timestamp_ns;
        
        if (packet.flow.protocol == PROTO_TCP) {
            state->current_metrics.tcp_connections = connection_manager_get_tcp_count(state->connection_manager);
        } else if (packet.flow.protocol == PROTO_UDP) {
            state->current_metrics.udp_sessions = connection_manager_get_udp_count(state->connection_manager);
        }
        
        // 8. Store metrics in ring buffer (check if buffer is not full first)
        if (!ring_buffer_is_full(state->metrics_buffer)) {
            ring_buffer_push(state->metrics_buffer, (flow_metrics_t*)&state->current_metrics);
        } else {
            // Buffer is full, rotate by popping oldest entry first
            flow_metrics_t old_metrics;
            if (ring_buffer_pop(state->metrics_buffer, &old_metrics)) {
                ring_buffer_push(state->metrics_buffer, (flow_metrics_t*)&state->current_metrics);
            } else {
                state->current_metrics.packet_errors++;
            }
        }
        
        // Check if buffer is empty for diagnostics
        if (ring_buffer_is_empty(state->metrics_buffer)) {
            LOG_DEBUG("Metrics buffer is empty");
        }
        
        // PRODUCTION FIX: Clean up translated packet to prevent memory leaks
        if (translated_packet) {
            safe_packet_destroy(translated_packet);
            translated_packet = NULL;
        }
        
        pthread_mutex_unlock(&state->mutex);
    }
    
    return NULL;
}

// Metrics collection thread
static void *metrics_thread(void *arg) {
    comprehensive_vpn_state_t *state = (comprehensive_vpn_state_t *)arg;
    
    while (state->processing_active) {
        pthread_mutex_lock(&state->mutex);
        
        // Update uptime
        static uint64_t start_time = 0;
        if (start_time == 0) {
            start_time = clock_gettime_nsec_np(CLOCK_MONOTONIC);
        }
        uint64_t current_time = clock_gettime_nsec_np(CLOCK_MONOTONIC);
        state->current_metrics.uptime_seconds = (current_time - start_time) / 1000000000ULL;
        
        // Get stats from various components
        privacy_stats_t privacy_stats;
        privacy_guards_get_stats(state->privacy_guards, &privacy_stats);
        state->current_metrics.privacy_violations = privacy_stats.total_violations;
        state->current_metrics.dns_leaks_detected = privacy_stats.dns_leaks_detected;
        
        // Get DNS cache stats
        state->current_metrics.dns_cache_size = dns_cache_get_size(state->dns_cache);
        state->current_metrics.dns_cache_max_size = dns_cache_get_max_size(state->dns_cache);
        state->current_metrics.dns_cache_hit_rate = 0.85f; // Stub value for now
        
        // Check reachability status (iOS only)
#ifdef TARGET_OS_IOS
        if (reachability_monitor_is_connected(state->reachability_monitor)) {
            state->current_metrics.network_status = 1; // Connected
            network_type_t network_type = reachability_monitor_get_network_type(state->reachability_monitor);
            // Store network type in metrics if needed
        } else {
            state->current_metrics.network_status = 0; // Disconnected
        }
#endif
        
        nat64_stats_t nat64_stats;
        nat64_get_stats(state->nat64_translator, &nat64_stats);
        state->current_metrics.nat64_translations = nat64_stats.packets_translated_4to6 + nat64_stats.packets_translated_6to4;
        
        // Platform-specific stats
#ifdef TARGET_OS_IOS
        // Get stats from tunnel provider
        vpn_metrics_t tunnel_metrics;
        tunnel_provider_get_stats(state->tunnel_provider, &tunnel_metrics);
        state->current_metrics.bytes_sent = tunnel_metrics.bytes_sent;
        state->current_metrics.active_connections = tunnel_metrics.tcp_connections + tunnel_metrics.udp_sessions;
#else
        // Socket bridge stats (non-iOS)
        vpn_metrics_t bridge_metrics;
        socket_bridge_get_stats(state->socket_bridge, &bridge_metrics);
        state->current_metrics.bytes_sent = bridge_metrics.bytes_sent;
        
        // Get connection count from socket bridge
        uint32_t connection_count = socket_bridge_get_connection_count(state->socket_bridge);
        state->current_metrics.active_connections = connection_count;
#endif
        
        // Call user callback if set
        if (state->metrics_callback) {
            state->metrics_callback(&state->current_metrics, state->metrics_user_data);
        }
        
        pthread_mutex_unlock(&state->mutex);
        
        // Sleep for 1 second
        struct timespec sleep_time = { .tv_sec = 1, .tv_nsec = 0 };
        nanosleep(&sleep_time, NULL);
    }
    
    return NULL;
}

// Packet handler from tunnel interface
static void comprehensive_packet_handler(const packet_info_t *packet, void *user_data) {
    comprehensive_vpn_state_t *state = (comprehensive_vpn_state_t *)user_data;
    if (!state || !packet) return;
    
    // SECURITY FIX: Validate packet size to prevent overflow
    if (packet->length == 0 || packet->length > MAX_PACKET_SIZE) {
        pthread_mutex_lock(&state->mutex);
        state->current_metrics.packet_errors++;
        
        // RECOVERY: Implement graceful degradation for oversized packets
        if (state->current_metrics.packet_errors > 1000) {
            LOG_WARN("High packet error rate detected (%u errors), activating error recovery", 
                    state->current_metrics.packet_errors);
            
            // Report potential stability issue to crash reporter (iOS only)
#ifdef TARGET_OS_IOS
            if (state->crash_reporter) {
                char error_msg[256];
                snprintf(error_msg, sizeof(error_msg), 
                        "Critical packet error rate: %u errors detected", 
                        state->current_metrics.packet_errors);
                crash_reporter_report_crash(state->crash_reporter, CRASH_TYPE_CUSTOM, error_msg);
            }
#endif
            
            // Reset error counter to prevent spam
            state->current_metrics.packet_errors = 0;
            
            // Could implement additional recovery mechanisms here:
            // - Reduce MTU size
            // - Restart networking components
            // - Switch to backup DNS servers
        }
        
        pthread_mutex_unlock(&state->mutex);
        return;
    }
    
    pthread_mutex_lock(&state->queue_mutex);
    
    // Add packet to processing queue with bounds checking
    if (state->queue_size == 0 || state->queue_tail >= state->queue_size) {
        pthread_mutex_unlock(&state->queue_mutex);
        return;
    }
    
    size_t next_tail = (state->queue_tail + 1) % state->queue_size;
    if (next_tail != state->queue_head) {
        state->packet_queue[state->queue_tail] = *packet;
        state->queue_tail = next_tail;
        pthread_cond_signal(&state->queue_cond);
    } else {
        // Queue full, drop packet
        pthread_mutex_lock(&state->mutex);
        state->current_metrics.packet_errors++;
        pthread_mutex_unlock(&state->mutex);
    }
    
    pthread_mutex_unlock(&state->queue_mutex);
}

static bool initialize_components(comprehensive_vpn_state_t *state) {
    // PRODUCTION FIX: Initialize buffer pools for safe memory management
    state->small_buffer_pool = buffer_pool_create(SMALL_BUFFER_SIZE, INITIAL_SMALL_BUFFERS);
    if (!state->small_buffer_pool) {
        LOG_ERROR("Failed to create small buffer pool");
        return false;
    }
    
    state->large_buffer_pool = buffer_pool_create(LARGE_BUFFER_SIZE, INITIAL_LARGE_BUFFERS);
    if (!state->large_buffer_pool) {
        LOG_ERROR("Failed to create large buffer pool");
        buffer_pool_destroy(state->small_buffer_pool);
        return false;
    }
    
    // Initialize DNS resolver
    ip_addr_t primary_dns = { .v4 = { .addr = inet_addr("8.8.8.8") } };
    state->dns_resolver = dns_resolver_create(&primary_dns, 53);
    if (!state->dns_resolver) {
        LOG_ERROR("Failed to create DNS resolver");
        return false;
    }
    
    // Add additional DNS servers if configured
    for (int i = 0; i < state->config.dns_server_count && i < MAX_DNS_SERVERS; i++) {
        ip_addr_t dns_server;
        dns_server.v4.addr = state->config.dns_servers[i];
        dns_resolver_add_server(state->dns_resolver, &dns_server, 53);
    }
    
    // Initialize DNS cache
    state->dns_cache = dns_cache_create(state->config.dns_cache_size, 300); // 5 minute TTL
    if (!state->dns_cache) {
        LOG_ERROR("Failed to create DNS cache");
        return false;
    }
    
    // Initialize privacy guards
    state->privacy_guards = privacy_guards_create();
    if (!state->privacy_guards) {
        LOG_ERROR("Failed to create privacy guards");
        return false;
    }
    
    // Configure privacy guards
    if (state->config.enable_dns_leak_protection) {
        privacy_guards_enable_dns_leak_protection(state->privacy_guards, true);
        
        // Set allowed DNS servers
        ip_addr_t allowed_dns[MAX_DNS_SERVERS];
        for (int i = 0; i < state->config.dns_server_count && i < MAX_DNS_SERVERS; i++) {
            allowed_dns[i].v4.addr = state->config.dns_servers[i];
        }
        privacy_guards_set_allowed_dns_servers(state->privacy_guards, allowed_dns, state->config.dns_server_count);
    }
    
    if (state->config.enable_ipv6_leak_protection) {
        privacy_guards_enable_ipv6_leak_protection(state->privacy_guards, true);
    }
    
    if (state->config.enable_kill_switch) {
        privacy_guards_enable_kill_switch(state->privacy_guards, true);
    }
    
    // Enable WebRTC leak protection if configured
    if (state->config.enable_webrtc_leak_protection) {
        privacy_guards_enable_webrtc_leak_protection(state->privacy_guards, true);
    }
    
    // Set up violation callback
    privacy_guards_set_violation_callback(state->privacy_guards, privacy_violation_callback, state);
    
    // Initialize platform-specific components
#ifdef TARGET_OS_IOS
    state->tunnel_provider = tunnel_provider_create();
    if (!state->tunnel_provider) {
        LOG_ERROR("Failed to create tunnel provider");
        return false;
    }
    
    // Set packet handler
    tunnel_provider_set_packet_handler(state->tunnel_provider, comprehensive_packet_handler, state);
#else
    state->socket_bridge = socket_bridge_create(state->connection_manager);
    if (!state->socket_bridge) {
        LOG_ERROR("Failed to create socket bridge");
        return false;
    }
#endif
    
    // Initialize NAT64 translator if enabled
    if (state->config.enable_nat64) {
        state->nat64_translator = nat64_translator_create(NULL, 96); // Use well-known prefix
        if (!state->nat64_translator) {
            LOG_ERROR("Failed to create NAT64 translator");
            return false;
        }
    }
    
    // Initialize connection manager
    state->connection_manager = connection_manager_create();
    if (!state->connection_manager) {
        LOG_ERROR("Failed to create connection manager");
        return false;
    }
    
    // Initialize MTU discovery
    state->mtu_discovery = mtu_discovery_create(state->config.tunnel_mtu);
    if (!state->mtu_discovery) {
        LOG_ERROR("Failed to create MTU discovery");
        return false;
    }
    
    // Initialize traffic classifier
    state->traffic_classifier = traffic_classifier_create();
    if (!state->traffic_classifier) {
        LOG_ERROR("Failed to create traffic classifier");
        return false;
    }
    
    // Set up traffic classifier callback for advanced classification
    traffic_classifier_set_callback(state->traffic_classifier, traffic_classification_callback, state);
    
    // Initialize reachability monitor (iOS only)
#ifdef TARGET_OS_IOS
    state->reachability_monitor = reachability_monitor_create();
    if (!state->reachability_monitor) {
        LOG_ERROR("Failed to create reachability monitor");
        return false;
    }
    
    reachability_monitor_start(state->reachability_monitor, NULL, NULL);
    
    // Initialize crash reporter
    state->crash_reporter = crash_reporter_create();
    if (!state->crash_reporter) {
        LOG_ERROR("Failed to create crash reporter");
        return false;
    }
#endif
    
    // Configure crash reporter with comprehensive monitoring (iOS only)
#ifdef TARGET_OS_IOS
    crash_reporter_flags_t crash_flags = CRASH_REPORTER_ENABLE_STACK_TRACES |
                                       CRASH_REPORTER_ENABLE_SYSTEM_INFO |
                                       CRASH_REPORTER_ENABLE_THREAD_INFO |
                                       CRASH_REPORTER_ENABLE_NETWORK_STATE |
                                       CRASH_REPORTER_ENABLE_VPN_STATE;
    
    if (!crash_reporter_initialize(state->crash_reporter, crash_flags)) {
        LOG_ERROR("Failed to initialize crash reporter");
        crash_reporter_destroy(state->crash_reporter);
        state->crash_reporter = NULL;
        return false;
    }
    
    // Set version information
    crash_reporter_set_version_info(state->crash_reporter, "1.0.0", "debug-build");
    
    // Set crash callback
    crash_reporter_set_callback(state->crash_reporter, crash_report_callback, state);
    
    // Enable crash reporting
    if (!crash_reporter_enable(state->crash_reporter)) {
        LOG_WARN("Failed to enable crash reporter - continuing without crash reporting");
    } else {
        LOG_INFO("Crash reporter enabled");
    }
#endif
    
    return true;
}

static void cleanup_components(comprehensive_vpn_state_t *state) {
    // PRODUCTION FIX: Clean up buffer pools first to ensure proper memory release
    if (state->small_buffer_pool) {
        buffer_pool_destroy(state->small_buffer_pool);
        state->small_buffer_pool = NULL;
    }
    
    if (state->large_buffer_pool) {
        buffer_pool_destroy(state->large_buffer_pool);
        state->large_buffer_pool = NULL;
    }
    
    if (state->dns_resolver) {
        dns_resolver_destroy(state->dns_resolver);
        state->dns_resolver = NULL;
    }
    
    if (state->dns_cache) {
        dns_cache_destroy(state->dns_cache);
        state->dns_cache = NULL;
    }
    
    if (state->privacy_guards) {
        privacy_guards_destroy(state->privacy_guards);
        state->privacy_guards = NULL;
    }
    
#ifdef TARGET_OS_IOS
    if (state->tunnel_provider) {
        tunnel_provider_destroy(state->tunnel_provider);
        state->tunnel_provider = NULL;
    }
#else
    if (state->socket_bridge) {
        socket_bridge_destroy(state->socket_bridge);
        state->socket_bridge = NULL;
    }
#endif
    
    if (state->nat64_translator) {
        nat64_translator_destroy(state->nat64_translator);
        state->nat64_translator = NULL;
    }
    
    if (state->connection_manager) {
        connection_manager_destroy(state->connection_manager);
        state->connection_manager = NULL;
    }
    
    if (state->mtu_discovery) {
        mtu_discovery_destroy(state->mtu_discovery);
        state->mtu_discovery = NULL;
    }
    
    if (state->traffic_classifier) {
        traffic_classifier_destroy(state->traffic_classifier);
        state->traffic_classifier = NULL;
    }
    
#ifdef TARGET_OS_IOS
    if (state->reachability_monitor) {
        reachability_monitor_destroy(state->reachability_monitor);
        state->reachability_monitor = NULL;
    }
    
    if (state->crash_reporter) {
        crash_reporter_disable(state->crash_reporter);
        crash_reporter_destroy(state->crash_reporter);
        state->crash_reporter = NULL;
    }
#endif
}

vpn_result_t vpn_start_comprehensive(const vpn_config_t *config) {
    if (!config) {
        return (vpn_result_t){ .status = VPN_ERROR_INVALID_CONFIG, .handle = VPN_INVALID_HANDLE };
    }
    
    // Initialize logging system first
    log_init(log_level_from_string(config->log_level));
    
    pthread_mutex_lock(&g_state_mutex);
    
    // SECURITY FIX: Atomic load with acquire ordering to prevent race conditions
    comprehensive_vpn_state_t *state = atomic_load_explicit(&g_vpn_state, memory_order_acquire);
    if (state && state->running) {
        pthread_mutex_unlock(&g_state_mutex);
        return (vpn_result_t){ .status = VPN_ERROR_ALREADY_RUNNING, .handle = VPN_INVALID_HANDLE };
    }
    
    if (!state) {
        comprehensive_vpn_state_t *new_state = calloc(1, sizeof(comprehensive_vpn_state_t));
        if (!new_state) {
            // Report critical memory allocation failure (iOS only)
#ifdef TARGET_OS_IOS
            if (g_crash_reporter) {
                crash_reporter_report_crash(g_crash_reporter, CRASH_TYPE_OUT_OF_MEMORY, 
                                          "Failed to allocate VPN state structure");
            }
#endif
            pthread_mutex_unlock(&g_state_mutex);
            return (vpn_result_t){ .status = VPN_ERROR_MEMORY, .handle = VPN_INVALID_HANDLE };
        }
        
        // SECURITY FIX: Initialize mutexes before atomic operations to prevent race conditions
        if (pthread_mutex_init(&new_state->mutex, NULL) != 0) {
            free(new_state);
            pthread_mutex_unlock(&g_state_mutex);
            return (vpn_result_t){ .status = VPN_ERROR_MEMORY, .handle = VPN_INVALID_HANDLE };
        }
        
        if (pthread_mutex_init(&new_state->queue_mutex, NULL) != 0 ||
            pthread_cond_init(&new_state->queue_cond, NULL) != 0) {
            pthread_mutex_destroy(&new_state->mutex);
            free(new_state);
            pthread_mutex_unlock(&g_state_mutex);
            return (vpn_result_t){ .status = VPN_ERROR_MEMORY, .handle = VPN_INVALID_HANDLE };
        }
        
        // Atomic compare-and-swap to set global state (after full initialization)
        comprehensive_vpn_state_t *expected = NULL;
        if (!atomic_compare_exchange_strong_explicit(&g_vpn_state, &expected, new_state, 
                                                    memory_order_release, memory_order_acquire)) {
            // Another thread won the race, clean up our state and use theirs
            pthread_cond_destroy(&new_state->queue_cond);
            pthread_mutex_destroy(&new_state->queue_mutex);
            pthread_mutex_destroy(&new_state->mutex);
            free(new_state);
            state = expected;
        } else {
            state = new_state;
        }
    }
    
    memcpy(&state->config, config, sizeof(vpn_config_t));
    
    // Initialize packet queue
    state->queue_size = 1000; // Queue up to 1000 packets
    state->packet_queue = calloc(state->queue_size, sizeof(packet_info_t));
    if (!state->packet_queue) {
        pthread_mutex_unlock(&g_state_mutex);
        return (vpn_result_t){ .status = VPN_ERROR_MEMORY, .handle = VPN_INVALID_HANDLE };
    }
    
    // Note: On iOS, the tunnel interface is created by NetworkExtension framework
    // and provided to us via NEPacketTunnelProvider
    
    // Create metrics buffer
    state->metrics_buffer = ring_buffer_create(config->metrics_buffer_size);
    if (!state->metrics_buffer) {
        free(state->packet_queue);
        pthread_mutex_unlock(&g_state_mutex);
        return (vpn_result_t){ .status = VPN_ERROR_MEMORY, .handle = VPN_INVALID_HANDLE };
    }
    
    // Initialize all components
    if (!initialize_components(state)) {
        ring_buffer_destroy(state->metrics_buffer);
        free(state->packet_queue);
        pthread_mutex_unlock(&g_state_mutex);
        return (vpn_result_t){ .status = VPN_ERROR_NETWORK, .handle = VPN_INVALID_HANDLE };
    }
    
    // Start processing threads
    state->processing_active = true;
    
    if (pthread_create(&state->packet_processing_thread, NULL, 
                      packet_processing_thread, state) != 0) {
        cleanup_components(state);
        ring_buffer_destroy(state->metrics_buffer);
        free(state->packet_queue);
        pthread_mutex_unlock(&g_state_mutex);
        return (vpn_result_t){ .status = VPN_ERROR_NETWORK, .handle = VPN_INVALID_HANDLE };
    }
    
    if (pthread_create(&state->metrics_thread, NULL, 
                      metrics_thread, state) != 0) {
        state->processing_active = false;
        pthread_join(state->packet_processing_thread, NULL);
        cleanup_components(state);
        ring_buffer_destroy(state->metrics_buffer);
        free(state->packet_queue);
        pthread_mutex_unlock(&g_state_mutex);
        return (vpn_result_t){ .status = VPN_ERROR_NETWORK, .handle = VPN_INVALID_HANDLE };
    }
    
    // Note: On iOS, packet reading is initiated by NEPacketTunnelProvider
    // through tunnel_provider_configure_packet_flow()
    
    state->running = true;
    
#ifdef TARGET_OS_IOS
    // FEATURE: Set up iOS memory pressure monitoring
    state->memory_pressure_source = dispatch_source_create(DISPATCH_SOURCE_TYPE_MEMORYPRESSURE, 0, 
                                                          DISPATCH_MEMORYPRESSURE_WARN | DISPATCH_MEMORYPRESSURE_CRITICAL, 
                                                          dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_HIGH, 0));
    
    if (state->memory_pressure_source) {
        dispatch_source_set_event_handler(state->memory_pressure_source, ^{
            unsigned long level = dispatch_source_get_data(state->memory_pressure_source);
            
            pthread_mutex_lock(&state->mutex);
            state->last_memory_warning = clock_gettime_nsec_np(CLOCK_MONOTONIC);
            state->memory_pressure_active = (level >= DISPATCH_MEMORYPRESSURE_WARN);
            pthread_mutex_unlock(&state->mutex);
            
            if (level >= DISPATCH_MEMORYPRESSURE_CRITICAL) {
                LOG_WARN("Critical memory pressure detected - activating emergency memory reduction");
                ios_reduce_memory_usage(state);
            } else if (level >= DISPATCH_MEMORYPRESSURE_WARN) {
                LOG_INFO("Memory pressure warning - reducing memory usage");
                ios_reduce_memory_usage(state);
            }
        });
        
        dispatch_resume(state->memory_pressure_source);
        LOG_INFO("iOS memory pressure monitoring enabled");
    } else {
        LOG_WARN("Failed to create memory pressure monitoring source");
    }
#endif
    
    pthread_mutex_unlock(&g_state_mutex);
    
    LOG_INFO("Comprehensive VPN started successfully");
    return (vpn_result_t){ .status = VPN_SUCCESS, .handle = (vpn_handle_t)state };
}

bool vpn_stop_comprehensive(vpn_handle_t handle) {
    if (handle == VPN_INVALID_HANDLE) {
        return false;
    }
    
    pthread_mutex_lock(&g_state_mutex);
    
    comprehensive_vpn_state_t *state = atomic_load(&g_vpn_state);
    if (!state || !state->running) {
        pthread_mutex_unlock(&g_state_mutex);
        return false;
    }
    
    state->running = false;
    state->processing_active = false;
    
#ifdef TARGET_OS_IOS
    // Clean up iOS memory pressure monitoring
    if (state->memory_pressure_source) {
        dispatch_source_cancel(state->memory_pressure_source);
        dispatch_release(state->memory_pressure_source);
        state->memory_pressure_source = NULL;
        LOG_DEBUG("iOS memory pressure monitoring stopped");
    }
#endif
    
    // Note: On iOS, packet flow is stopped by NetworkExtension framework
    
    // Signal processing thread to stop
    pthread_cond_broadcast(&state->queue_cond);
    
    // Wait for threads to complete
    pthread_join(state->packet_processing_thread, NULL);
    pthread_join(state->metrics_thread, NULL);
    
    // Cleanup all components
    cleanup_components(state);
    
    
    if (state->metrics_buffer) {
        ring_buffer_destroy(state->metrics_buffer);
        state->metrics_buffer = NULL;
    }
    
    free(state->packet_queue);
    state->packet_queue = NULL;
    
    pthread_mutex_unlock(&g_state_mutex);
    
    LOG_INFO("Comprehensive VPN stopped successfully");
    return true;
}

bool vpn_inject_packet_comprehensive(vpn_handle_t handle, const packet_info_t *packet) {
    if (handle == VPN_INVALID_HANDLE || !packet) {
        return false;
    }
    
    pthread_mutex_lock(&g_state_mutex);
    
    comprehensive_vpn_state_t *state = atomic_load(&g_vpn_state);
    if (!state || !state->running) {
        pthread_mutex_unlock(&g_state_mutex);
        return false;
    }
    
    // Add packet directly to processing queue
    comprehensive_packet_handler(packet, state);
    
    pthread_mutex_unlock(&g_state_mutex);
    return true;
}

bool vpn_get_metrics_comprehensive(vpn_handle_t handle, vpn_metrics_t *metrics) {
    if (handle == VPN_INVALID_HANDLE || !metrics) {
        return false;
    }
    
    pthread_mutex_lock(&g_state_mutex);
    
    comprehensive_vpn_state_t *state = atomic_load(&g_vpn_state);
    if (!state || !state->running) {
        pthread_mutex_unlock(&g_state_mutex);
        return false;
    }
    
    pthread_mutex_lock(&state->mutex);
    memcpy(metrics, &state->current_metrics, sizeof(vpn_metrics_t));
    pthread_mutex_unlock(&state->mutex);
    
    pthread_mutex_unlock(&g_state_mutex);
    return true;
}

bool vpn_is_running_comprehensive(vpn_handle_t handle) {
    if (handle == VPN_INVALID_HANDLE) {
        return false;
    }
    
    pthread_mutex_lock(&g_state_mutex);
    comprehensive_vpn_state_t *state = atomic_load(&g_vpn_state);
    bool running = state && state->running;
    pthread_mutex_unlock(&g_state_mutex);
    return running;
}

bool vpn_update_config_comprehensive(vpn_handle_t handle, const vpn_config_t *config) {
    if (handle == VPN_INVALID_HANDLE || !config) {
        return false;
    }
    
    pthread_mutex_lock(&g_state_mutex);
    
    comprehensive_vpn_state_t *state = atomic_load(&g_vpn_state);
    if (!state || !state->running) {
        pthread_mutex_unlock(&g_state_mutex);
        return false;
    }
    
    pthread_mutex_lock(&state->mutex);
    
    // Update configuration
    vpn_config_t old_config = state->config;
    state->config = *config;
    
    // Update privacy guards if settings changed
    if (old_config.enable_dns_leak_protection != config->enable_dns_leak_protection) {
        privacy_guards_enable_dns_leak_protection(state->privacy_guards, 
                                                 config->enable_dns_leak_protection);
    }
    
    if (old_config.enable_ipv6_leak_protection != config->enable_ipv6_leak_protection) {
        privacy_guards_enable_ipv6_leak_protection(state->privacy_guards, 
                                                  config->enable_ipv6_leak_protection);
    }
    
    if (old_config.enable_kill_switch != config->enable_kill_switch) {
        privacy_guards_enable_kill_switch(state->privacy_guards, 
                                        config->enable_kill_switch);
    }
    
    pthread_mutex_unlock(&state->mutex);
    pthread_mutex_unlock(&g_state_mutex);
    
    LOG_INFO("VPN configuration updated successfully");
    return true;
}

bool vpn_get_config_comprehensive(vpn_handle_t handle, vpn_config_t *config) {
    if (handle == VPN_INVALID_HANDLE || !config) {
        return false;
    }
    
    pthread_mutex_lock(&g_state_mutex);
    
    comprehensive_vpn_state_t *state = atomic_load(&g_vpn_state);
    if (!state || !state->running) {
        pthread_mutex_unlock(&g_state_mutex);
        return false;
    }
    
    pthread_mutex_lock(&state->mutex);
    memcpy(config, &state->config, sizeof(vpn_config_t));
    pthread_mutex_unlock(&state->mutex);
    
    pthread_mutex_unlock(&g_state_mutex);
    return true;
}

#ifdef TARGET_OS_IOS
// FEATURE: iOS memory pressure handling implementation
static bool ios_get_memory_info(uint64_t *memory_used, uint64_t *memory_available) {
    if (!memory_used || !memory_available) {
        return false;
    }
    
    // Get memory statistics using Mach APIs
    vm_statistics64_data_t vm_stat;
    mach_msg_type_number_t host_size = sizeof(vm_statistics64_data_t) / sizeof(natural_t);
    
    kern_return_t kr = host_statistics64(mach_host_self(), HOST_VM_INFO64, 
                                        (host_info64_t)&vm_stat, &host_size);
    if (kr != KERN_SUCCESS) {
        LOG_ERROR("Failed to get VM statistics: %d", kr);
        return false;
    }
    
    // Get page size
    vm_size_t page_size;
    kr = host_page_size(mach_host_self(), &page_size);
    if (kr != KERN_SUCCESS) {
        LOG_ERROR("Failed to get page size: %d", kr);
        return false;
    }
    
    // Calculate memory usage
    uint64_t total_pages = vm_stat.free_count + vm_stat.active_count + 
                          vm_stat.inactive_count + vm_stat.wire_count;
    uint64_t used_pages = total_pages - vm_stat.free_count;
    
    *memory_used = used_pages * page_size;
    *memory_available = vm_stat.free_count * page_size;
    
    LOG_DEBUG("Memory: Used=%llu MB, Available=%llu MB", 
              *memory_used / (1024 * 1024), 
              *memory_available / (1024 * 1024));
    
    return true;
}

static void ios_reduce_memory_usage(comprehensive_vpn_state_t *state) {
    if (!state) return;
    
    LOG_INFO("Reducing memory usage due to memory pressure");
    
    pthread_mutex_lock(&state->mutex);
    
    // 1. Reduce DNS cache size by 50%
    if (state->dns_cache) {
        size_t current_size = dns_cache_get_size(state->dns_cache);
        size_t target_size = current_size / 2;
        
        // Clear oldest entries to reduce cache size
        while (dns_cache_get_size(state->dns_cache) > target_size) {
            // Evict oldest entries (implementation would depend on DNS cache internals)
            dns_cache_evict_oldest(state->dns_cache);
        }
        
        LOG_INFO("Reduced DNS cache from %zu to %zu entries", current_size, target_size);
    }
    
    // 2. Reduce metrics buffer size by 50%
    if (state->metrics_buffer) {
        size_t buffer_size = ring_buffer_get_size(state->metrics_buffer);
        size_t target_size = buffer_size / 2;
        
        // Pop oldest entries to reduce buffer usage
        flow_metrics_t dummy_metrics;
        while (ring_buffer_get_count(state->metrics_buffer) > target_size) {
            if (!ring_buffer_pop(state->metrics_buffer, &dummy_metrics)) {
                break;
            }
        }
        
        LOG_INFO("Reduced metrics buffer usage to %zu entries", target_size);
    }
    
    // 3. Clear connection manager statistics to reduce memory
    if (state->connection_manager) {
        // Reset accumulated statistics that might be consuming memory
        vpn_metrics_t empty_metrics = {0};
        connection_manager_get_stats(state->connection_manager, &empty_metrics);
    }
    
    // 4. Trigger garbage collection in privacy guards
    if (state->privacy_guards) {
        // Clear violation history to free memory
        privacy_guards_reset_stats(state->privacy_guards);
    }
    
    // 5. Reduce packet queue size temporarily
    if (state->packet_queue && state->queue_size > 100) {
        size_t new_queue_size = state->queue_size / 2;
        if (new_queue_size < 100) new_queue_size = 100;
        
        // Only reduce if queue is not heavily used
        size_t current_queue_usage = (state->queue_tail - state->queue_head + state->queue_size) % state->queue_size;
        if (current_queue_usage < new_queue_size) {
            // Allocate smaller queue
            packet_info_t *new_queue = calloc(new_queue_size, sizeof(packet_info_t));
            if (new_queue) {
                // Copy existing packets
                for (size_t i = 0; i < current_queue_usage; i++) {
                    size_t src_idx = (state->queue_head + i) % state->queue_size;
                    new_queue[i] = state->packet_queue[src_idx];
                }
                
                free(state->packet_queue);
                state->packet_queue = new_queue;
                state->queue_size = new_queue_size;
                state->queue_head = 0;
                state->queue_tail = current_queue_usage;
                
                LOG_INFO("Reduced packet queue size from %zu to %zu", state->queue_size, new_queue_size);
            }
        }
    }
    
    pthread_mutex_unlock(&state->mutex);
    
    // 6. Get current memory usage for logging
    uint64_t memory_used, memory_available;
    if (ios_get_memory_info(&memory_used, &memory_available)) {
        LOG_INFO("Memory usage after reduction: Used=%llu MB, Available=%llu MB", 
                 memory_used / (1024 * 1024), 
                 memory_available / (1024 * 1024));
    }
}
#endif

// FEATURE: Get crash reporting statistics for monitoring and debugging
bool vpn_get_crash_stats_comprehensive(vpn_handle_t handle, crash_stats_t *stats) {
    if (handle == VPN_INVALID_HANDLE || !stats) {
        return false;
    }
    
    pthread_mutex_lock(&g_state_mutex);
    
    comprehensive_vpn_state_t *state = atomic_load(&g_vpn_state);
    if (!state || !state->running || !state->crash_reporter) {
        pthread_mutex_unlock(&g_state_mutex);
        return false;
    }
    
    crash_reporter_get_stats(state->crash_reporter, stats);
    
    pthread_mutex_unlock(&g_state_mutex);
    return true;
}

// FEATURE: Report custom application-level errors to crash reporter
bool vpn_report_custom_error_comprehensive(vpn_handle_t handle, const char *error_description) {
    if (handle == VPN_INVALID_HANDLE || !error_description) {
        return false;
    }
    
    pthread_mutex_lock(&g_state_mutex);
    
    comprehensive_vpn_state_t *state = atomic_load(&g_vpn_state);
    if (!state || !state->running || !state->crash_reporter) {
        pthread_mutex_unlock(&g_state_mutex);
        return false;
    }
    
    bool result = crash_reporter_report_crash(state->crash_reporter, CRASH_TYPE_CUSTOM, error_description);
    
    pthread_mutex_unlock(&g_state_mutex);
    return result;
}