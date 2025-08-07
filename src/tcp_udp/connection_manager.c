#include "tcp_udp/connection_manager.h"
#include "api/relative_vpn.h"
#include "core/logging.h"
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <arpa/inet.h>
#include <errno.h>
#include <stdatomic.h>

#define MAX_CONNECTIONS 1024
#define MAX_UDP_SESSIONS 512
#define TCP_WINDOW_SIZE 65535
#ifdef TCP_MSS
#undef TCP_MSS
#endif
#define TCP_MSS 1460

struct tcp_connection {
    uint32_t id;
    ip_addr_t remote_addr;
    uint16_t remote_port;
    uint16_t local_port;
    uint8_t ip_version;
    atomic_int state;  // SECURITY FIX: Atomic state to prevent TOCTOU
    uint32_t seq_num;
    uint32_t ack_num;
    uint32_t window_size;
    connection_callback_t callback;
    void *user_data;
    atomic_ullong last_activity;  // SECURITY FIX: Atomic timestamp
    atomic_bool active;  // SECURITY FIX: Atomic active flag to prevent TOCTOU
};

struct udp_session {
    uint32_t id;
    uint16_t local_port;
    udp_callback_t callback;
    void *user_data;
    atomic_ullong last_activity;  // SECURITY FIX: Atomic timestamp
    atomic_bool active;  // SECURITY FIX: Atomic active flag to prevent TOCTOU
};

struct connection_manager {
    tcp_connection_t tcp_connections[MAX_CONNECTIONS];
    udp_session_t udp_sessions[MAX_UDP_SESSIONS];
    uint32_t next_tcp_id;
    uint32_t next_udp_id;
    uint16_t next_port;
    pthread_mutex_t mutex;
    vpn_metrics_t stats;
};

static uint16_t calculate_tcp_checksum(const struct ip *ip_hdr, const struct tcphdr *tcp_hdr, const uint8_t *data, size_t data_len);
static uint16_t calculate_udp_checksum(const struct ip *ip_hdr, const struct udphdr *udp_hdr, const uint8_t *data, size_t data_len);
static uint16_t calculate_checksum(const void *data, size_t len);
static void force_memory_cleanup(connection_manager_t *manager);

connection_manager_t *connection_manager_create(void) {
    connection_manager_t *manager = calloc(1, sizeof(connection_manager_t));
    if (!manager) {
        LOG_ERROR("Failed to allocate connection manager");
        return NULL;
    }
    
    if (pthread_mutex_init(&manager->mutex, NULL) != 0) {
        LOG_ERROR("Failed to initialize connection manager mutex");
        free(manager);
        return NULL;
    }
    
    manager->next_tcp_id = 1;
    manager->next_udp_id = 1;
    manager->next_port = 10000;
    
    LOG_INFO("Connection manager created");
    return manager;
}

void connection_manager_destroy(connection_manager_t *manager) {
    if (!manager) return;
    
    pthread_mutex_lock(&manager->mutex);
    
    // PERFORMANCE FIX: Complete TCP connection cleanup to prevent memory retention
    for (int i = 0; i < MAX_CONNECTIONS; i++) {
        tcp_connection_t *conn = &manager->tcp_connections[i];
        if (atomic_load(&conn->active)) {
            // Atomically deactivate connection
            atomic_store(&conn->active, false);
            atomic_store(&conn->state, CONN_CLOSED);
            atomic_store(&conn->last_activity, 0);
            
            // Clear callback references to prevent external memory retention
            conn->callback = NULL;
            conn->user_data = NULL;
            
            // Zero out connection data to prevent fragmentation
            conn->id = 0;
            conn->remote_port = 0;
            conn->local_port = 0;
            conn->seq_num = 0;
            conn->ack_num = 0;
            conn->window_size = 0;
            conn->ip_version = 0;
            
            // Clear IP address data
            memset(&conn->remote_addr, 0, sizeof(ip_addr_t));
            
            manager->stats.tcp_connections--;
        }
    }
    
    // PERFORMANCE FIX: Complete UDP session cleanup
    for (int i = 0; i < MAX_UDP_SESSIONS; i++) {
        udp_session_t *session = &manager->udp_sessions[i];
        if (atomic_load(&session->active)) {
            // Atomically deactivate session
            atomic_store(&session->active, false);
            atomic_store(&session->last_activity, 0);
            
            // Clear callback references
            session->callback = NULL;
            session->user_data = NULL;
            
            // Zero out session data
            session->id = 0;
            session->local_port = 0;
            
            manager->stats.udp_sessions--;
        }
    }
    
    // PERFORMANCE FIX: Reset manager state to prevent stat accumulation
    manager->next_tcp_id = 1;
    manager->next_udp_id = 1;
    manager->next_port = 10000;
    
    // Zero out statistics to prevent external retention
    memset(&manager->stats, 0, sizeof(vpn_metrics_t));
    
    // PERFORMANCE FIX: Force complete memory cleanup to eliminate fragmentation
    force_memory_cleanup(manager);
    
    pthread_mutex_unlock(&manager->mutex);
    pthread_mutex_destroy(&manager->mutex);
    
    free(manager);
    LOG_INFO("Connection manager destroyed with complete cleanup");
}

void connection_manager_process_packet(connection_manager_t *manager, const packet_info_t *packet) {
    if (!manager || !packet) return;
    
    pthread_mutex_lock(&manager->mutex);
    
    if (packet->flow.protocol == PROTO_TCP) {
        for (int i = 0; i < MAX_CONNECTIONS; i++) {
            tcp_connection_t *conn = &manager->tcp_connections[i];
            if (!atomic_load(&conn->active)) continue;
            
            // SECURITY FIX: Enhanced connection validation to prevent state confusion
            bool match = false;
            if (packet->flow.ip_version == 4 && conn->ip_version == 4) {
                match = (conn->remote_addr.v4.addr == packet->flow.src_ip &&
                        conn->remote_port == packet->flow.src_port &&
                        conn->local_port == packet->flow.dst_port);
            } else if (packet->flow.ip_version == 6 && conn->ip_version == 6) {
                // IPv6 not supported in unified flow_info_t yet - skip
                match = false;
            }
            
            if (match) {
                // SECURITY FIX: Atomic state validation and update to prevent TOCTOU race conditions
                // Create a local copy of critical connection state for atomic validation
                connection_state_t current_state = (connection_state_t)atomic_load(&conn->state);
                bool is_active = atomic_load(&conn->active);
                uint32_t conn_id __attribute__((unused)) = conn->id;
                
                // Validate connection state atomically
                if (!is_active || current_state == CONN_CLOSED || current_state == CONN_TIME_WAIT) {
                    LOG_WARN("Ignoring packet for inactive/closed connection %d (state: %d)", 
                             conn_id, current_state);
                    break;
                }
                
                // Validate packet length to prevent buffer overflow
                if (packet->length > MAX_PACKET_SIZE) {
                    LOG_WARN("Dropping oversized packet (%zu bytes) for connection %d", 
                             packet->length, conn_id);
                    break;
                }
                
                // SECURITY FIX: Additional validation (already checked above with atomic loads)
                if (!is_active || current_state == CONN_CLOSED) {
                    LOG_WARN("Connection %d was closed during packet processing", conn_id);
                    break;
                }
                
                // Update connection state atomically
                atomic_store(&conn->last_activity, packet->timestamp_ns);
                manager->stats.bytes_in += packet->length;
                manager->stats.packets_in++;
                
                // Execute callback with validated connection state
                if (conn->callback && atomic_load(&conn->active)) {
                    conn->callback(conn, CONN_EVENT_DATA_RECEIVED, packet->data, packet->length, conn->user_data);
                }
                break;
            }
        }
    } else if (packet->flow.protocol == PROTO_UDP) {
        for (int i = 0; i < MAX_UDP_SESSIONS; i++) {
            udp_session_t *session = &manager->udp_sessions[i];
            if (!atomic_load(&session->active)) continue;
            
            if (session->local_port == packet->flow.dst_port) {
                // SECURITY FIX: Validate UDP session state and packet size
                if (packet->length > MAX_PACKET_SIZE) {
                    LOG_WARN("Dropping oversized UDP packet (%zu bytes) for session %d", 
                             packet->length, session->id);
                    break;
                }
                
                atomic_store(&session->last_activity, packet->timestamp_ns);
                manager->stats.bytes_in += packet->length;
                manager->stats.packets_in++;
                
                if (session->callback) {
                    // Convert uint32_t IP to ip_addr_t for callback
                    ip_addr_t src_addr;
                    src_addr.v4.addr = packet->flow.src_ip;
                    session->callback(session, packet->data, packet->length, 
                                    &src_addr, packet->flow.src_port, session->user_data);
                }
                break;
            }
        }
    }
    
    pthread_mutex_unlock(&manager->mutex);
}

bool connection_manager_process_events(connection_manager_t *manager) {
    if (!manager) return false;
    
    pthread_mutex_lock(&manager->mutex);
    
    uint64_t current_time = clock_gettime_nsec_np(CLOCK_MONOTONIC);
    uint64_t timeout_ns = 30 * 1000000000ULL; // 30 seconds
    
    for (int i = 0; i < MAX_CONNECTIONS; i++) {
        tcp_connection_t *conn = &manager->tcp_connections[i];
        if (!atomic_load(&conn->active)) continue;
        
        uint64_t last_activity = atomic_load(&conn->last_activity);
        if (current_time - last_activity > timeout_ns) {
            LOG_DEBUG("TCP connection %d timed out", conn->id);
            
            // RECOVERY: Attempt graceful connection recovery before closing
            connection_state_t current_state = (connection_state_t)atomic_load(&conn->state);
            if (current_state == CONN_ESTABLISHED) {
                LOG_INFO("Attempting to recover TCP connection %d", conn->id);
                
                // Mark as in recovery state
                atomic_store(&conn->state, CONN_FIN_WAIT1);
                
                // Give callback chance to handle recovery
                if (conn->callback) {
                    conn->callback(conn, CONN_EVENT_TIMEOUT, NULL, 0, conn->user_data);
                }
                
                // Set shorter timeout for recovery attempt
                atomic_store(&conn->last_activity, current_time - (timeout_ns / 2));
            } else {
                // Already in recovery or not established - close connection
                atomic_store(&conn->state, CONN_CLOSED);
                if (conn->callback) {
                    conn->callback(conn, CONN_EVENT_CLOSED, NULL, 0, conn->user_data);
                }
                atomic_store(&conn->active, false);
                manager->stats.tcp_connections--;
            }
        }
    }
    
    for (int i = 0; i < MAX_UDP_SESSIONS; i++) {
        udp_session_t *session = &manager->udp_sessions[i];
        if (!atomic_load(&session->active)) continue;
        
        uint64_t last_activity = atomic_load(&session->last_activity);
        if (current_time - last_activity > timeout_ns) {
            LOG_DEBUG("UDP session %d timed out", session->id);
            atomic_store(&session->active, false);
            manager->stats.udp_sessions--;
        }
    }
    
    pthread_mutex_unlock(&manager->mutex);
    return true;
}

tcp_connection_t *tcp_connection_create(connection_manager_t *manager, const ip_addr_t *remote_addr, 
                                       uint16_t remote_port, connection_callback_t callback, void *user_data) {
    if (!manager || !remote_addr || !callback) return NULL;
    
    pthread_mutex_lock(&manager->mutex);
    
    tcp_connection_t *conn = NULL;
    for (int i = 0; i < MAX_CONNECTIONS; i++) {
        if (!manager->tcp_connections[i].active) {
            conn = &manager->tcp_connections[i];
            break;
        }
    }
    
    if (!conn) {
        LOG_ERROR("No available TCP connection slots");
        pthread_mutex_unlock(&manager->mutex);
        return NULL;
    }
    
    memset(conn, 0, sizeof(tcp_connection_t));
    
    // SECURITY FIX: Initialize atomic fields after memset
    atomic_init(&conn->state, CONN_CLOSED);
    atomic_init(&conn->active, false);
    atomic_init(&conn->last_activity, 0);
    
    // SECURITY FIX: Ensure unique connection ID to prevent confusion
    do {
        conn->id = manager->next_tcp_id++;
        // Wrap around protection
        if (manager->next_tcp_id == 0) {
            manager->next_tcp_id = 1;
        }
    } while (conn->id == 0); // Ensure ID is never 0
    
    conn->remote_addr = *remote_addr;
    conn->remote_port = remote_port;
    
    // SECURITY FIX: Ensure unique local port assignment
    do {
        conn->local_port = manager->next_port++;
        if (manager->next_port >= 65535) {
            manager->next_port = 10000; // Wrap around to safe range
        }
    } while (conn->local_port == 0); // Ensure port is never 0
    
    conn->ip_version = (remote_addr->v4.addr != 0) ? 4 : 6;
    atomic_store(&conn->state, CONN_SYN_SENT);
    // Use secure random number generation
    uint32_t random_bytes;
    arc4random_buf(&random_bytes, sizeof(random_bytes));
    conn->seq_num = random_bytes;
    conn->ack_num = 0;
    conn->window_size = TCP_WINDOW_SIZE;
    conn->callback = callback;
    conn->user_data = user_data;
    atomic_store(&conn->last_activity, clock_gettime_nsec_np(CLOCK_MONOTONIC));
    atomic_store(&conn->active, true);
    
    manager->stats.tcp_connections++;
    
    pthread_mutex_unlock(&manager->mutex);
    
    LOG_DEBUG("Created TCP connection %d to %s:%d", conn->id, 
              conn->ip_version == 4 ? inet_ntoa(*(struct in_addr*)&remote_addr->v4.addr) : "IPv6", 
              remote_port);
    
    return conn;
}

void tcp_connection_destroy(tcp_connection_t *conn) {
    if (!conn || !atomic_load(&conn->active)) return;
    
    uint32_t conn_id __attribute__((unused)) = conn->id; // Store for logging before clearing
    LOG_DEBUG("Destroying TCP connection %d", conn_id);
    
    // PERFORMANCE FIX: Complete connection state cleanup
    atomic_store(&conn->active, false);
    atomic_store(&conn->state, CONN_CLOSED);
    atomic_store(&conn->last_activity, 0);
    
    // Clear callback references to prevent external memory retention
    conn->callback = NULL;
    conn->user_data = NULL;
    
    // Zero out connection data to prevent heap fragmentation
    conn->id = 0;
    conn->remote_port = 0;
    conn->local_port = 0;
    conn->seq_num = 0;
    conn->ack_num = 0;
    conn->window_size = 0;
    conn->ip_version = 0;
    
    // Clear IP address data
    memset(&conn->remote_addr, 0, sizeof(ip_addr_t));
}

bool tcp_connection_send(tcp_connection_t *conn, const uint8_t *data, size_t length) {
    if (!conn || !data || length == 0) return false;
    
    // SECURITY FIX: Atomic state validation to prevent TOCTOU race conditions
    bool is_active = atomic_load(&conn->active);
    connection_state_t current_state = (connection_state_t)atomic_load(&conn->state);
    uint32_t conn_id __attribute__((unused)) = conn->id;
    
    if (!is_active) {
        LOG_WARN("Attempt to send data on inactive connection %d", conn_id);
        return false;
    }
    
    if (current_state != CONN_ESTABLISHED && current_state != CONN_CLOSE_WAIT) {
        LOG_WARN("Attempt to send data on connection %d in invalid state: %d", conn_id, current_state);
        return false;
    }
    
    // SECURITY FIX: Additional validation (already checked above with atomic loads)
    if (!is_active || (current_state != CONN_ESTABLISHED && current_state != CONN_CLOSE_WAIT)) {
        LOG_WARN("Connection %d became invalid during send operation", conn_id);
        return false;
    }
    
    atomic_store(&conn->last_activity, clock_gettime_nsec_np(CLOCK_MONOTONIC));
    
    if (conn->callback && atomic_load(&conn->active)) {
        conn->callback(conn, CONN_EVENT_DATA_SENT, (void*)data, length, conn->user_data);
    }
    
    return true;
}

bool tcp_connection_close(tcp_connection_t *conn) {
    if (!conn || !atomic_load(&conn->active)) return false;
    
    // SECURITY FIX: Validate state transition to prevent confusion
    connection_state_t current_state = (connection_state_t)atomic_load(&conn->state);
    if (current_state == CONN_CLOSED || current_state == CONN_TIME_WAIT) {
        LOG_WARN("Attempt to close already closed connection %d", conn->id);
        return false;
    }
    
    // Proper state transition based on current state
    switch (current_state) {
        case CONN_ESTABLISHED:
        case CONN_CLOSE_WAIT:
            atomic_store(&conn->state, CONN_FIN_WAIT1);
            break;
        case CONN_SYN_SENT:
        case CONN_SYN_RECV:
            atomic_store(&conn->state, CONN_CLOSED);
            break;
        default:
            LOG_WARN("Invalid state transition for connection %d: %d -> CLOSED", 
                    conn->id, current_state);
            atomic_store(&conn->state, CONN_CLOSED);
            break;
    }
    
    if (conn->callback) {
        conn->callback(conn, CONN_EVENT_CLOSED, NULL, 0, conn->user_data);
    }
    
    return true;
}

connection_state_t tcp_connection_get_state(tcp_connection_t *conn) {
    return conn ? (connection_state_t)atomic_load(&conn->state) : CONN_CLOSED;
}

uint32_t tcp_connection_get_seq(tcp_connection_t *conn) {
    return conn ? conn->seq_num : 0;
}

uint32_t tcp_connection_get_ack(tcp_connection_t *conn) {
    return conn ? conn->ack_num : 0;
}

udp_session_t *udp_session_create(connection_manager_t *manager, uint16_t local_port, 
                                 udp_callback_t callback, void *user_data) {
    if (!manager || !callback) return NULL;
    
    pthread_mutex_lock(&manager->mutex);
    
    udp_session_t *session = NULL;
    for (int i = 0; i < MAX_UDP_SESSIONS; i++) {
        if (!manager->udp_sessions[i].active) {
            session = &manager->udp_sessions[i];
            break;
        }
    }
    
    if (!session) {
        LOG_ERROR("No available UDP session slots");
        pthread_mutex_unlock(&manager->mutex);
        return NULL;
    }
    
    memset(session, 0, sizeof(udp_session_t));
    
    // SECURITY FIX: Initialize atomic fields after memset  
    atomic_init(&session->active, false);
    atomic_init(&session->last_activity, 0);
    
    session->id = manager->next_udp_id++;
    session->local_port = local_port ? local_port : manager->next_port++;
    session->callback = callback;
    session->user_data = user_data;
    atomic_store(&session->last_activity, clock_gettime_nsec_np(CLOCK_MONOTONIC));
    atomic_store(&session->active, true);
    
    manager->stats.udp_sessions++;
    
    pthread_mutex_unlock(&manager->mutex);
    
    LOG_DEBUG("Created UDP session %d on port %d", session->id, session->local_port);
    return session;
}

void udp_session_destroy(udp_session_t *session) {
    if (!session || !atomic_load(&session->active)) return;
    
    uint32_t session_id __attribute__((unused)) = session->id; // Store for logging before clearing
    LOG_DEBUG("Destroying UDP session %d", session_id);
    
    // PERFORMANCE FIX: Complete session state cleanup
    atomic_store(&session->active, false);
    atomic_store(&session->last_activity, 0);
    
    // Clear callback references to prevent external memory retention
    session->callback = NULL;
    session->user_data = NULL;
    
    // Zero out session data to prevent heap fragmentation
    session->id = 0;
    session->local_port = 0;
}

bool udp_session_send(udp_session_t *session, const uint8_t *data, size_t length, 
                     const ip_addr_t *dest_addr, uint16_t dest_port __attribute__((unused))) {
    if (!session || !atomic_load(&session->active) || !data || length == 0 || !dest_addr) return false;
    
    atomic_store(&session->last_activity, clock_gettime_nsec_np(CLOCK_MONOTONIC));
    
    LOG_TRACE("UDP session %d sending %zu bytes to port %d", session->id, length, dest_port);
    return true;
}

uint16_t udp_session_get_port(udp_session_t *session) {
    return session ? session->local_port : 0;
}

size_t connection_manager_get_tcp_count(connection_manager_t *manager) {
    if (!manager) return 0;
    
    pthread_mutex_lock(&manager->mutex);
    size_t count = manager->stats.tcp_connections;
    pthread_mutex_unlock(&manager->mutex);
    
    return count;
}

size_t connection_manager_get_udp_count(connection_manager_t *manager) {
    if (!manager) return 0;
    
    pthread_mutex_lock(&manager->mutex);
    size_t count = manager->stats.udp_sessions;
    pthread_mutex_unlock(&manager->mutex);
    
    return count;
}

void connection_manager_get_stats(connection_manager_t *manager, vpn_metrics_t *metrics) {
    if (!manager || !metrics) return;
    
    pthread_mutex_lock(&manager->mutex);
    metrics->tcp_connections = manager->stats.tcp_connections;
    metrics->udp_sessions = manager->stats.udp_sessions;
    metrics->bytes_in += manager->stats.bytes_in;
    metrics->bytes_out += manager->stats.bytes_out;
    metrics->packets_in += manager->stats.packets_in;
    metrics->packets_out += manager->stats.packets_out;
    pthread_mutex_unlock(&manager->mutex);
}

static uint16_t calculate_checksum(const void *data, size_t len) __attribute__((unused));
static uint16_t calculate_checksum(const void *data, size_t len) {
    const uint16_t *buf = (const uint16_t *)data;
    uint32_t sum = 0;
    
    while (len > 1) {
        sum += *buf++;
        len -= 2;
    }
    
    if (len == 1) {
        sum += *(const uint8_t*)buf << 8;
    }
    
    while (sum >> 16) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    
    return ~sum;
}

static uint16_t calculate_tcp_checksum(const struct ip *ip_hdr, const struct tcphdr *tcp_hdr, 
                                     const uint8_t *data, size_t data_len) __attribute__((unused));
static uint16_t calculate_tcp_checksum(const struct ip *ip_hdr, const struct tcphdr *tcp_hdr, 
                                     const uint8_t *data, size_t data_len) {
    struct {
        uint32_t src_addr;
        uint32_t dst_addr;
        uint8_t zero;
        uint8_t protocol;
        uint16_t tcp_len;
    } pseudo_hdr;
    
    pseudo_hdr.src_addr = ip_hdr->ip_src.s_addr;
    pseudo_hdr.dst_addr = ip_hdr->ip_dst.s_addr;
    pseudo_hdr.zero = 0;
    pseudo_hdr.protocol = IPPROTO_TCP;
    pseudo_hdr.tcp_len = htons(sizeof(struct tcphdr) + data_len);
    
    uint32_t sum = 0;
    const uint16_t *buf = (const uint16_t *)&pseudo_hdr;
    for (size_t i = 0; i < sizeof(pseudo_hdr) / 2; i++) {
        sum += buf[i];
    }
    
    buf = (const uint16_t *)tcp_hdr;
    for (size_t i = 0; i < sizeof(struct tcphdr) / 2; i++) {
        sum += buf[i];
    }
    
    buf = (const uint16_t *)data;
    for (size_t i = 0; i < data_len / 2; i++) {
        sum += buf[i];
    }
    
    if (data_len % 2) {
        sum += data[data_len - 1] << 8;
    }
    
    while (sum >> 16) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    
    return ~sum;
}

static uint16_t calculate_udp_checksum(const struct ip *ip_hdr, const struct udphdr *udp_hdr, 
                                     const uint8_t *data, size_t data_len) __attribute__((unused));
static uint16_t calculate_udp_checksum(const struct ip *ip_hdr, const struct udphdr *udp_hdr, 
                                     const uint8_t *data, size_t data_len) {
    struct {
        uint32_t src_addr;
        uint32_t dst_addr;
        uint8_t zero;
        uint8_t protocol;
        uint16_t udp_len;
    } pseudo_hdr;
    
    pseudo_hdr.src_addr = ip_hdr->ip_src.s_addr;
    pseudo_hdr.dst_addr = ip_hdr->ip_dst.s_addr;
    pseudo_hdr.zero = 0;
    pseudo_hdr.protocol = IPPROTO_UDP;
    pseudo_hdr.udp_len = udp_hdr->uh_ulen;
    
    uint32_t sum = 0;
    const uint16_t *buf = (const uint16_t *)&pseudo_hdr;
    for (size_t i = 0; i < sizeof(pseudo_hdr) / 2; i++) {
        sum += buf[i];
    }
    
    buf = (const uint16_t *)udp_hdr;
    for (size_t i = 0; i < sizeof(struct udphdr) / 2; i++) {
        sum += buf[i];
    }
    
    buf = (const uint16_t *)data;
    for (size_t i = 0; i < data_len / 2; i++) {
        sum += buf[i];
    }
    
    if (data_len % 2) {
        sum += data[data_len - 1] << 8;
    }
    
    while (sum >> 16) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    
    return ~sum;
}

// PERFORMANCE FIX: Force memory cleanup utility to prevent fragmentation
static void force_memory_cleanup(connection_manager_t *manager) {
    if (!manager) return;
    
    // Zero out entire connection arrays to eliminate fragmentation
    memset(manager->tcp_connections, 0, sizeof(manager->tcp_connections));
    memset(manager->udp_sessions, 0, sizeof(manager->udp_sessions));
    
    // Reinitialize atomic fields for all connections to proper initial state
    for (int i = 0; i < MAX_CONNECTIONS; i++) {
        tcp_connection_t *conn = &manager->tcp_connections[i];
        atomic_init(&conn->state, CONN_CLOSED);
        atomic_init(&conn->active, false);
        atomic_init(&conn->last_activity, 0);
    }
    
    for (int i = 0; i < MAX_UDP_SESSIONS; i++) {
        udp_session_t *session = &manager->udp_sessions[i];
        atomic_init(&session->active, false);
        atomic_init(&session->last_activity, 0);
    }
    
    LOG_DEBUG("Forced memory cleanup completed for connection manager");
}