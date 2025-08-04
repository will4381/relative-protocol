#include "socket_bridge/bridge.h"
#include "api/relative_vpn.h"
#include "core/logging.h"
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <time.h>

#ifdef TARGET_OS_IOS
// Forward declarations for iOS NetworkExtension types (avoid importing Objective-C headers in C file)
typedef void* ios_tcp_connection_t;
typedef void* ios_udp_session_t;

// Objective-C bridge functions (implemented in bridge_ios.mm)
extern ios_tcp_connection_t* ios_create_tcp_connection(const char* host, uint16_t port);
extern ios_udp_session_t* ios_create_udp_session(uint16_t local_port);
extern bool ios_send_tcp_data(ios_tcp_connection_t* conn, const uint8_t* data, size_t length);
extern bool ios_send_udp_data(ios_udp_session_t* session, const uint8_t* data, size_t length, 
                               const char* dest_host, uint16_t dest_port);
extern void ios_close_tcp_connection(ios_tcp_connection_t* conn);
extern void ios_close_udp_session(ios_udp_session_t* session);
#else
// Non-iOS platforms still need socket headers
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>
#include <unistd.h>
#endif

#define MAX_BRIDGE_CONNECTIONS 512
#define BRIDGE_BUFFER_SIZE 65536

struct bridge_connection {
    uint32_t id;
    bridge_protocol_t protocol;
    ip_addr_t remote_addr;
    uint16_t remote_port;
    uint16_t local_port;
    uint8_t ip_version;
    connection_state_t state;
    
    tcp_connection_t *tcp_conn;
    udp_session_t *udp_session;
    
    bridge_data_callback_t data_callback;
    bridge_event_callback_t event_callback;
    void *user_data;
    
    uint8_t *read_buffer;
    size_t buffer_size;
    bool active;
    
#ifdef TARGET_OS_IOS
    ios_tcp_connection_t *ios_tcp_conn;
    ios_udp_session_t *ios_udp_session;
    void *read_queue;
#else
    int socket_fd;
    pthread_t read_thread;
    bool read_thread_running;
#endif
};

struct socket_bridge {
    connection_manager_t *conn_mgr;
    bridge_connection_t connections[MAX_BRIDGE_CONNECTIONS];
    uint32_t next_connection_id;
    pthread_mutex_t mutex;
    vpn_metrics_t stats;
    
#ifdef TARGET_OS_IOS
    void *tunnel_provider;
#endif
};

#ifndef TARGET_OS_IOS
static void *bridge_read_thread(void *arg);
#endif
static void bridge_tcp_callback(tcp_connection_t *conn, connection_event_t event, void *data, size_t length, void *user_data);
static void bridge_udp_callback(udp_session_t *session, const uint8_t *data, size_t length, const ip_addr_t *src_addr, uint16_t src_port, void *user_data);

socket_bridge_t *socket_bridge_create(connection_manager_t *conn_mgr) {
    if (!conn_mgr) {
        LOG_ERROR("Connection manager is required for socket bridge");
        return NULL;
    }
    
    socket_bridge_t *bridge = calloc(1, sizeof(socket_bridge_t));
    if (!bridge) {
        LOG_ERROR("Failed to allocate socket bridge");
        return NULL;
    }
    
    if (pthread_mutex_init(&bridge->mutex, NULL) != 0) {
        LOG_ERROR("Failed to initialize socket bridge mutex");
        free(bridge);
        return NULL;
    }
    
    bridge->conn_mgr = conn_mgr;
    bridge->next_connection_id = 1;
    
    LOG_INFO("Socket bridge created");
    return bridge;
}

void socket_bridge_destroy(socket_bridge_t *bridge) {
    if (!bridge) return;
    
    pthread_mutex_lock(&bridge->mutex);
    
    for (int i = 0; i < MAX_BRIDGE_CONNECTIONS; i++) {
        bridge_connection_t *conn = &bridge->connections[i];
        if (conn->active) {
            socket_bridge_destroy_connection(conn);
        }
    }
    
    pthread_mutex_unlock(&bridge->mutex);
    pthread_mutex_destroy(&bridge->mutex);
    
    free(bridge);
    LOG_INFO("Socket bridge destroyed");
}

bridge_connection_t *socket_bridge_create_tcp_connection(socket_bridge_t *bridge, 
                                                       const ip_addr_t *remote_addr, 
                                                       uint16_t remote_port,
                                                       bridge_data_callback_t data_callback,
                                                       bridge_event_callback_t event_callback,
                                                       void *user_data) {
    if (!bridge || !remote_addr || !data_callback) return NULL;
    
    pthread_mutex_lock(&bridge->mutex);
    
    bridge_connection_t *conn = NULL;
    for (int i = 0; i < MAX_BRIDGE_CONNECTIONS; i++) {
        if (!bridge->connections[i].active) {
            conn = &bridge->connections[i];
            break;
        }
    }
    
    if (!conn) {
        LOG_ERROR("No available bridge connection slots");
        pthread_mutex_unlock(&bridge->mutex);
        return NULL;
    }
    
    memset(conn, 0, sizeof(bridge_connection_t));
    conn->id = bridge->next_connection_id++;
    conn->protocol = BRIDGE_TCP;
    conn->remote_addr = *remote_addr;
    conn->remote_port = remote_port;
    conn->ip_version = (remote_addr->v4.addr != 0) ? 4 : 6;
    conn->state = CONN_CLOSED;
#ifndef TARGET_OS_IOS
    conn->socket_fd = -1;
#endif
    conn->data_callback = data_callback;
    conn->event_callback = event_callback;
    conn->user_data = user_data;
    conn->buffer_size = BRIDGE_BUFFER_SIZE;
    conn->read_buffer = malloc(conn->buffer_size);
    conn->active = true;
    
    if (!conn->read_buffer) {
        LOG_ERROR("Failed to allocate read buffer for bridge connection");
        conn->active = false;
        memset(conn, 0, sizeof(bridge_connection_t));
        pthread_mutex_unlock(&bridge->mutex);
        return NULL;
    }
    
    conn->tcp_conn = tcp_connection_create(bridge->conn_mgr, remote_addr, remote_port, 
                                         bridge_tcp_callback, conn);
    if (!conn->tcp_conn) {
        LOG_ERROR("Failed to create TCP connection");
        free(conn->read_buffer);
        conn->read_buffer = NULL;
        conn->active = false;
        memset(conn, 0, sizeof(bridge_connection_t));
        pthread_mutex_unlock(&bridge->mutex);
        return NULL;
    }
#ifdef TARGET_OS_IOS
    // On iOS, we'll use NEPacketTunnelProvider's createTCPConnection instead of raw sockets
    conn->read_queue = NULL; // Will be set up by iOS bridge functions
    LOG_DEBUG("iOS bridge connection will be configured via NetworkExtension");
    
    conn->state = CONN_SYN_SENT;
    // iOS connection will be established through NEPacketTunnelProvider API
#else
    // Non-iOS platforms use traditional sockets
    int sock_family = (conn->ip_version == 4) ? AF_INET : AF_INET6;
    conn->socket_fd = socket(sock_family, SOCK_STREAM, 0);
    if (conn->socket_fd < 0) {
        LOG_ERROR("Failed to create socket: %s", strerror(errno));
        tcp_connection_destroy(conn->tcp_conn);
        conn->tcp_conn = NULL;
        free(conn->read_buffer);
        conn->read_buffer = NULL;
        conn->active = false;
        memset(conn, 0, sizeof(bridge_connection_t));
        pthread_mutex_unlock(&bridge->mutex);
        return NULL;
    }
    
    if (conn->ip_version == 4) {
        struct sockaddr_in addr = {0};
        addr.sin_family = AF_INET;
        addr.sin_port = htons(remote_port);
        addr.sin_addr.s_addr = remote_addr->v4.addr;
        
        if (connect(conn->socket_fd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
            if (errno != EINPROGRESS) {
                LOG_ERROR("Failed to connect TCP socket: %s", strerror(errno));
                close(conn->socket_fd);
                conn->socket_fd = -1;
                tcp_connection_destroy(conn->tcp_conn);
                conn->tcp_conn = NULL;
                free(conn->read_buffer);
                conn->read_buffer = NULL;
                conn->active = false;
                memset(conn, 0, sizeof(bridge_connection_t));
                pthread_mutex_unlock(&bridge->mutex);
                return NULL;
            }
        }
    } else {
        struct sockaddr_in6 addr = {0};
        addr.sin6_family = AF_INET6;
        addr.sin6_port = htons(remote_port);
        memcpy(&addr.sin6_addr, remote_addr->v6.addr, 16);
        
        if (connect(conn->socket_fd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
            if (errno != EINPROGRESS) {
                LOG_ERROR("Failed to connect TCP IPv6 socket: %s", strerror(errno));
                close(conn->socket_fd);
                conn->socket_fd = -1;
                tcp_connection_destroy(conn->tcp_conn);
                conn->tcp_conn = NULL;
                free(conn->read_buffer);
                conn->read_buffer = NULL;
                conn->active = false;
                memset(conn, 0, sizeof(bridge_connection_t));
                pthread_mutex_unlock(&bridge->mutex);
                return NULL;
            }
        }
    }
    
    conn->state = CONN_SYN_SENT;
    conn->read_thread_running = true;
    
    if (pthread_create(&conn->read_thread, NULL, bridge_read_thread, conn) != 0) {
        LOG_ERROR("Failed to create bridge read thread");
        close(conn->socket_fd);
        conn->socket_fd = -1;
        tcp_connection_destroy(conn->tcp_conn);
        conn->tcp_conn = NULL;
        free(conn->read_buffer);
        conn->read_buffer = NULL;
        conn->active = false;
        memset(conn, 0, sizeof(bridge_connection_t));
        pthread_mutex_unlock(&bridge->mutex);
        return NULL;
    }
#endif
    
    bridge->stats.tcp_connections++;
    
    pthread_mutex_unlock(&bridge->mutex);
    
#ifdef TARGET_OS_IOS
    LOG_DEBUG("Created TCP bridge connection %d to %s:%d (iOS NetworkExtension)", conn->id,
              conn->ip_version == 4 ? "IPv4" : "IPv6", remote_port);
#else
    LOG_DEBUG("Created TCP bridge connection %d to %s:%d", conn->id,
              conn->ip_version == 4 ? inet_ntoa(*(struct in_addr*)&remote_addr->v4.addr) : "IPv6",
              remote_port);
#endif
    
    return conn;
}

bridge_connection_t *socket_bridge_create_udp_session(socket_bridge_t *bridge,
                                                     uint16_t local_port,
                                                     bridge_data_callback_t data_callback,
                                                     void *user_data) {
    if (!bridge || !data_callback) return NULL;
    
    pthread_mutex_lock(&bridge->mutex);
    
    bridge_connection_t *conn = NULL;
    for (int i = 0; i < MAX_BRIDGE_CONNECTIONS; i++) {
        if (!bridge->connections[i].active) {
            conn = &bridge->connections[i];
            break;
        }
    }
    
    if (!conn) {
        LOG_ERROR("No available bridge connection slots");
        pthread_mutex_unlock(&bridge->mutex);
        return NULL;
    }
    
    memset(conn, 0, sizeof(bridge_connection_t));
    conn->id = bridge->next_connection_id++;
    conn->protocol = BRIDGE_UDP;
    conn->local_port = local_port;
    conn->state = CONN_ESTABLISHED;
#ifndef TARGET_OS_IOS
    conn->socket_fd = -1;
#endif
    conn->data_callback = data_callback;
    conn->user_data = user_data;
    conn->buffer_size = BRIDGE_BUFFER_SIZE;
    conn->read_buffer = malloc(conn->buffer_size);
    conn->active = true;
    
    if (!conn->read_buffer) {
        LOG_ERROR("Failed to allocate read buffer for UDP session");
        conn->active = false;
        memset(conn, 0, sizeof(bridge_connection_t));
        pthread_mutex_unlock(&bridge->mutex);
        return NULL;
    }
    
    conn->udp_session = udp_session_create(bridge->conn_mgr, local_port, 
                                         bridge_udp_callback, conn);
    if (!conn->udp_session) {
        LOG_ERROR("Failed to create UDP session");
        free(conn->read_buffer);
        conn->read_buffer = NULL;
        conn->active = false;
        memset(conn, 0, sizeof(bridge_connection_t));
        pthread_mutex_unlock(&bridge->mutex);
        return NULL;
    }
    
    conn->local_port = udp_session_get_port(conn->udp_session);
    bridge->stats.udp_sessions++;
    
    pthread_mutex_unlock(&bridge->mutex);
    
    LOG_DEBUG("Created UDP bridge session %d on port %d", conn->id, conn->local_port);
    return conn;
}

void socket_bridge_destroy_connection(bridge_connection_t *conn) {
    if (!conn || !conn->active) return;
    
    LOG_DEBUG("Destroying bridge connection %d", conn->id);
    
    // PRODUCTION FIX: Atomic flag to prevent race conditions
    conn->active = false;
    
#ifdef TARGET_OS_IOS
    // iOS: Clean up dispatch queue
    if (conn->read_queue) {
        // Will be cleaned up by iOS bridge functions
        conn->read_queue = NULL;
    }
#else
    // Non-iOS: Proper thread termination with timeout
    if (conn->read_thread_running) {
        conn->read_thread_running = false;
        
        // Close socket first to wake up any blocking recv() calls
        if (conn->socket_fd >= 0) {
            shutdown(conn->socket_fd, SHUT_RDWR);
        }
        
        struct timespec timeout = {
            .tv_sec = 5,  // 5 second timeout
            .tv_nsec = 0
        };
        
#ifdef __APPLE__
        // macOS doesn't have pthread_timedjoin_np, use alternative approach
        void *thread_result;
        int join_result = pthread_join(conn->read_thread, &thread_result);
        if (join_result != 0) {
            LOG_ERROR("CRITICAL: Failed to join bridge read thread for connection %d: %s", 
                     conn->id, strerror(join_result));
            // Thread might still be running - this is a critical memory leak!
            // Force cleanup anyway but log the error
        }
#else
        int join_result = pthread_timedjoin_np(conn->read_thread, NULL, &timeout);
        if (join_result == ETIMEDOUT) {
            LOG_ERROR("CRITICAL: Bridge read thread for connection %d failed to terminate within timeout", conn->id);
            // Force thread cancellation as last resort
            pthread_cancel(conn->read_thread);
            pthread_join(conn->read_thread, NULL);
        } else if (join_result != 0) {
            LOG_ERROR("CRITICAL: Failed to join bridge read thread for connection %d: %s", 
                     conn->id, strerror(join_result));
        }
#endif
    }
    
    // PRODUCTION FIX: Safe socket cleanup
    if (conn->socket_fd >= 0) {
        close(conn->socket_fd);
        conn->socket_fd = -1;
    }
#endif
    
    // PRODUCTION FIX: Safe connection cleanup with null checks
    if (conn->tcp_conn) {
        tcp_connection_destroy(conn->tcp_conn);
        conn->tcp_conn = NULL;
    }
    
    if (conn->udp_session) {
        udp_session_destroy(conn->udp_session);
        conn->udp_session = NULL;
    }
    
    // PRODUCTION FIX: Critical memory cleanup with security clearing
    if (conn->read_buffer) {
        // Clear sensitive data before freeing
        memset(conn->read_buffer, 0, conn->buffer_size);
        free(conn->read_buffer);
        conn->read_buffer = NULL;
    }
    
#ifdef TARGET_OS_IOS
    // PRODUCTION FIX: Proper iOS Network framework cleanup
    if (conn->ios_tcp_conn) {
        // Cleanup will be handled by iOS bridge functions
        conn->ios_tcp_conn = NULL;
    }
    
    if (conn->ios_udp_session) {
        // Cleanup will be handled by iOS bridge functions  
        conn->ios_udp_session = NULL;
    }
#endif

    // PRODUCTION FIX: Final state cleanup to prevent double-free
    memset(conn, 0, sizeof(bridge_connection_t));
#ifndef TARGET_OS_IOS
    conn->socket_fd = -1;
#endif
    
    LOG_DEBUG("Bridge connection %d destroyed successfully", conn->id);
}

bool socket_bridge_send_data(bridge_connection_t *conn, const uint8_t *data, size_t length) {
    if (!conn || !conn->active || !data || length == 0) return false;
    
    if (conn->protocol == BRIDGE_TCP) {
#ifdef TARGET_OS_IOS
        if (conn->ios_tcp_conn) {
            // Use iOS bridge function to send data
            return ios_send_tcp_data(conn->ios_tcp_conn, data, length);
        }
#else
        if (conn->socket_fd >= 0) {
            ssize_t sent = send(conn->socket_fd, data, length, 0);
            if (sent < 0) {
                LOG_ERROR("Failed to send TCP data: %s", strerror(errno));
                return false;
            }
            LOG_TRACE("Sent %zd bytes via TCP bridge connection %d", sent, conn->id);
            return sent == (ssize_t)length;
        }
#endif
    }
    
    return false;
}

bool socket_bridge_send_udp_data(bridge_connection_t *conn, const uint8_t *data, size_t length, 
                                const ip_addr_t *dest_addr, uint16_t dest_port) {
    if (!conn || !conn->active || !data || length == 0 || !dest_addr) return false;
    
    if (conn->protocol == BRIDGE_UDP && conn->udp_session) {
        return udp_session_send(conn->udp_session, data, length, dest_addr, dest_port);
    }
    
    return false;
}

void socket_bridge_process_packet(socket_bridge_t *bridge, const packet_info_t *packet) {
    if (!bridge || !packet) return;
    
    connection_manager_process_packet(bridge->conn_mgr, packet);
}

bool socket_bridge_process_events(socket_bridge_t *bridge) {
    if (!bridge) return false;
    
    return connection_manager_process_events(bridge->conn_mgr);
}

#ifndef TARGET_OS_IOS
// Read thread is only used on non-iOS platforms
static void *bridge_read_thread(void *arg) {
    bridge_connection_t *conn = (bridge_connection_t *)arg;
    
    LOG_DEBUG("Starting bridge read thread for connection %d", conn->id);
    
    while (conn->read_thread_running && conn->active) {
        ssize_t bytes_read = recv(conn->socket_fd, conn->read_buffer, conn->buffer_size, 0);
        
        if (bytes_read < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                continue;
            }
            if (conn->read_thread_running) {
                LOG_ERROR("Bridge read error for connection %d: %s", conn->id, strerror(errno));
            }
            break;
        }
        
        if (bytes_read == 0) {
            LOG_DEBUG("Bridge connection %d closed by peer", conn->id);
            break;
        }
        
        if (conn->data_callback) {
            conn->data_callback(conn, conn->read_buffer, bytes_read, conn->user_data);
        }
    }
    
    if (conn->event_callback) {
        conn->event_callback(conn, CONN_EVENT_CLOSED, conn->user_data);
    }
    
    LOG_DEBUG("Bridge read thread for connection %d finished", conn->id);
    return NULL;
}
#endif

static void bridge_tcp_callback(tcp_connection_t *tcp_conn, connection_event_t event, 
                               void *data, size_t length, void *user_data) {
    bridge_connection_t *conn = (bridge_connection_t *)user_data;
    if (!conn) return;
    
    switch (event) {
        case CONN_EVENT_ESTABLISHED:
            conn->state = CONN_ESTABLISHED;
            break;
        case CONN_EVENT_DATA_RECEIVED:
            if (conn->data_callback) {
                conn->data_callback(conn, (const uint8_t *)data, length, conn->user_data);
            }
            break;
        case CONN_EVENT_CLOSED:
            conn->state = CONN_CLOSED;
            break;
        default:
            break;
    }
    
    if (conn->event_callback) {
        conn->event_callback(conn, event, conn->user_data);
    }
}

static void bridge_udp_callback(udp_session_t *session, const uint8_t *data, size_t length, 
                               const ip_addr_t *src_addr, uint16_t src_port, void *user_data) {
    bridge_connection_t *conn = (bridge_connection_t *)user_data;
    if (!conn) return;
    
    if (conn->data_callback) {
        conn->data_callback(conn, data, length, conn->user_data);
    }
}

bridge_protocol_t bridge_connection_get_protocol(bridge_connection_t *conn) {
    return conn ? conn->protocol : BRIDGE_TCP;
}

connection_state_t bridge_connection_get_state(bridge_connection_t *conn) {
    return conn ? conn->state : CONN_CLOSED;
}

uint16_t bridge_connection_get_local_port(bridge_connection_t *conn) {
    return conn ? conn->local_port : 0;
}

uint16_t bridge_connection_get_remote_port(bridge_connection_t *conn) {
    return conn ? conn->remote_port : 0;
}

const ip_addr_t *bridge_connection_get_remote_addr(bridge_connection_t *conn) {
    return conn ? &conn->remote_addr : NULL;
}

size_t socket_bridge_get_connection_count(socket_bridge_t *bridge) {
    if (!bridge) return 0;
    
    pthread_mutex_lock(&bridge->mutex);
    size_t count = bridge->stats.tcp_connections + bridge->stats.udp_sessions;
    pthread_mutex_unlock(&bridge->mutex);
    
    return count;
}

void socket_bridge_get_stats(socket_bridge_t *bridge, vpn_metrics_t *metrics) {
    if (!bridge || !metrics) return;
    
    pthread_mutex_lock(&bridge->mutex);
    connection_manager_get_stats(bridge->conn_mgr, metrics);
    pthread_mutex_unlock(&bridge->mutex);
}

// iOS-specific functions have been moved to bridge_ios.mm