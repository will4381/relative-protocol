#include "dns/resolver.h"
#include "core/logging.h"
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <errno.h>
#include <time.h>

#define MAX_DNS_SERVERS 8
#define MAX_CONCURRENT_QUERIES 256
#define DNS_HEADER_SIZE 12
#define DNS_PORT 53

struct dns_query {
    uint16_t transaction_id;
    char hostname[DNS_MAX_NAME_LENGTH + 1];
    dns_record_type_t type;
    dns_query_callback_t callback;
    void *user_data;
    uint64_t start_time_ns;
    uint32_t timeout_ms;
    uint8_t retry_count;
    uint8_t max_retries;
    bool completed;
    bool active;
};

struct dns_server {
    ip_addr_t addr;
    uint16_t port;
    uint8_t ip_version;
    bool active;
};

struct dns_resolver {
    struct dns_server servers[MAX_DNS_SERVERS];
    size_t server_count;
    struct dns_query queries[MAX_CONCURRENT_QUERIES];
    uint16_t next_transaction_id;
    uint32_t default_timeout_ms;
    uint8_t default_max_retries;
    bool dnssec_enabled;
    
    int socket_fd_v4;
    int socket_fd_v6;
    pthread_t worker_thread;
    bool worker_running;
    pthread_mutex_t mutex;
    
    uint32_t stats_queries_sent;
    uint32_t stats_responses_received;
    uint32_t stats_timeouts;
    uint32_t stats_errors;
};

static void *dns_worker_thread(void *arg);
static bool dns_send_query(dns_resolver_t *resolver, dns_query_t *query);
static dns_query_t *dns_find_query_by_id(dns_resolver_t *resolver, uint16_t transaction_id);
static void dns_complete_query(dns_query_t *query, dns_response_t *response);

dns_resolver_t *dns_resolver_create(const ip_addr_t *server_addr, uint16_t server_port) {
    dns_resolver_t *resolver = calloc(1, sizeof(dns_resolver_t));
    if (!resolver) {
        LOG_ERROR("Failed to allocate DNS resolver");
        return NULL;
    }
    
    if (pthread_mutex_init(&resolver->mutex, NULL) != 0) {
        LOG_ERROR("Failed to initialize DNS resolver mutex");
        free(resolver);
        return NULL;
    }
    
    resolver->socket_fd_v4 = socket(AF_INET, SOCK_DGRAM, 0);
    if (resolver->socket_fd_v4 < 0) {
        LOG_ERROR("Failed to create IPv4 DNS socket: %s", strerror(errno));
        pthread_mutex_destroy(&resolver->mutex);
        free(resolver);
        return NULL;
    }
    
    resolver->socket_fd_v6 = socket(AF_INET6, SOCK_DGRAM, 0);
    if (resolver->socket_fd_v6 < 0) {
        LOG_WARN("Failed to create IPv6 DNS socket: %s", strerror(errno));
    }
    
    // Transaction IDs are now generated randomly - no sequential counter needed
    resolver->default_timeout_ms = DNS_DEFAULT_TIMEOUT_MS;
    resolver->default_max_retries = 3;
    resolver->dnssec_enabled = false;
    
    if (server_addr) {
        dns_resolver_add_server(resolver, server_addr, server_port ? server_port : DNS_PORT);
    }
    
    resolver->worker_running = true;
    if (pthread_create(&resolver->worker_thread, NULL, dns_worker_thread, resolver) != 0) {
        LOG_ERROR("Failed to create DNS worker thread");
        close(resolver->socket_fd_v4);
        if (resolver->socket_fd_v6 >= 0) close(resolver->socket_fd_v6);
        pthread_mutex_destroy(&resolver->mutex);
        free(resolver);
        return NULL;
    }
    
    LOG_INFO("DNS resolver created");
    return resolver;
}

void dns_resolver_destroy(dns_resolver_t *resolver) {
    if (!resolver) return;
    
    resolver->worker_running = false;
    
    if (pthread_join(resolver->worker_thread, NULL) != 0) {
        LOG_WARN("Failed to join DNS worker thread");
    }
    
    pthread_mutex_lock(&resolver->mutex);
    
    for (int i = 0; i < MAX_CONCURRENT_QUERIES; i++) {
        if (resolver->queries[i].active) {
            resolver->queries[i].active = false;
        }
    }
    
    pthread_mutex_unlock(&resolver->mutex);
    
    close(resolver->socket_fd_v4);
    if (resolver->socket_fd_v6 >= 0) close(resolver->socket_fd_v6);
    
    pthread_mutex_destroy(&resolver->mutex);
    free(resolver);
    
    LOG_INFO("DNS resolver destroyed");
}

bool dns_resolver_add_server(dns_resolver_t *resolver, const ip_addr_t *server_addr, uint16_t server_port) {
    if (!resolver || !server_addr) return false;
    
    pthread_mutex_lock(&resolver->mutex);
    
    if (resolver->server_count >= MAX_DNS_SERVERS) {
        LOG_ERROR("Maximum DNS servers reached");
        pthread_mutex_unlock(&resolver->mutex);
        return false;
    }
    
    struct dns_server *server = &resolver->servers[resolver->server_count];
    server->addr = *server_addr;
    server->port = server_port;
    server->ip_version = (server_addr->v4.addr != 0) ? 4 : 6;
    server->active = true;
    
    resolver->server_count++;
    
    pthread_mutex_unlock(&resolver->mutex);
    
    LOG_INFO("Added DNS server %s:%d", 
             server->ip_version == 4 ? inet_ntoa(*(struct in_addr*)&server_addr->v4.addr) : "IPv6",
             server_port);
    
    return true;
}

bool dns_resolver_remove_server(dns_resolver_t *resolver, const ip_addr_t *server_addr, uint16_t server_port) {
    if (!resolver || !server_addr) return false;
    
    pthread_mutex_lock(&resolver->mutex);
    
    for (size_t i = 0; i < resolver->server_count; i++) {
        struct dns_server *server = &resolver->servers[i];
        
        bool match = false;
        if (server->ip_version == 4 && server_addr->v4.addr != 0) {
            match = (server->addr.v4.addr == server_addr->v4.addr && server->port == server_port);
        } else if (server->ip_version == 6 && server_addr->v4.addr == 0) {
            match = (memcmp(server->addr.v6.addr, server_addr->v6.addr, 16) == 0 && server->port == server_port);
        }
        
        if (match) {
            memmove(&resolver->servers[i], &resolver->servers[i + 1], 
                   (resolver->server_count - i - 1) * sizeof(struct dns_server));
            resolver->server_count--;
            pthread_mutex_unlock(&resolver->mutex);
            return true;
        }
    }
    
    pthread_mutex_unlock(&resolver->mutex);
    return false;
}

dns_query_t *dns_resolver_query_async(dns_resolver_t *resolver, const char *hostname, 
                                     dns_record_type_t type, dns_query_callback_t callback, void *user_data) {
    if (!resolver || !hostname || !callback || !dns_is_valid_hostname(hostname)) return NULL;
    
    pthread_mutex_lock(&resolver->mutex);
    
    dns_query_t *query = NULL;
    for (int i = 0; i < MAX_CONCURRENT_QUERIES; i++) {
        if (!resolver->queries[i].active) {
            query = &resolver->queries[i];
            break;
        }
    }
    
    if (!query) {
        LOG_ERROR("No available query slots");
        pthread_mutex_unlock(&resolver->mutex);
        return NULL;
    }
    
    memset(query, 0, sizeof(dns_query_t));
    // SECURITY FIX: Use cryptographically secure random transaction IDs
    arc4random_buf(&query->transaction_id, sizeof(query->transaction_id));
    strncpy(query->hostname, hostname, DNS_MAX_NAME_LENGTH);
    query->type = type;
    query->callback = callback;
    query->user_data = user_data;
    query->start_time_ns = clock_gettime_nsec_np(CLOCK_MONOTONIC);
    query->timeout_ms = resolver->default_timeout_ms;
    query->max_retries = resolver->default_max_retries;
    query->retry_count = 0;
    query->completed = false;
    query->active = true;
    
    if (!dns_send_query(resolver, query)) {
        LOG_ERROR("Failed to send DNS query for %s", hostname);
        query->active = false;
        pthread_mutex_unlock(&resolver->mutex);
        return NULL;
    }
    
    pthread_mutex_unlock(&resolver->mutex);
    
    LOG_DEBUG("Started DNS query for %s (type %d, id %d)", hostname, type, query->transaction_id);
    return query;
}

bool dns_resolver_query_sync(dns_resolver_t *resolver, const char *hostname, 
                            dns_record_type_t type, dns_response_t *response, uint32_t timeout_ms) {
    if (!resolver || !hostname || !response) return false;
    
    bool query_completed = false;
    dns_response_t *received_response = NULL;
    
    // Simple synchronous implementation - would use semaphore in real implementation
    dns_query_t *query = dns_resolver_query_async(resolver, hostname, type, NULL, NULL);
    if (!query) return false;
    
    uint64_t start_time = clock_gettime_nsec_np(CLOCK_MONOTONIC);
    uint64_t timeout_ns = timeout_ms * 1000000ULL;
    
    while (!query_completed && !query->completed) {
        if (clock_gettime_nsec_np(CLOCK_MONOTONIC) - start_time > timeout_ns) {
            dns_query_cancel(query);
            return false;
        }
        usleep(1000);
    }
    
    if (received_response) {
        *response = *received_response;
        return true;
    }
    
    return false;
}

void dns_query_cancel(dns_query_t *query) {
    if (!query) return;
    
    query->active = false;
    query->completed = true;
}

bool dns_query_is_completed(dns_query_t *query) {
    return query ? query->completed : true;
}

const char *dns_query_get_hostname(dns_query_t *query) {
    return query ? query->hostname : NULL;
}

dns_record_type_t dns_query_get_type(dns_query_t *query) {
    return query ? query->type : DNS_TYPE_A;
}

void dns_response_destroy(dns_response_t *response) {
    if (!response) return;
    
    free(response->answers);
    response->answers = NULL;
    response->answer_count = 0;
}

static void *dns_worker_thread(void *arg) {
    dns_resolver_t *resolver = (dns_resolver_t *)arg;
    
    LOG_DEBUG("DNS worker thread started");
    
    while (resolver->worker_running) {
        fd_set read_fds;
        FD_ZERO(&read_fds);
        
        int max_fd = -1;
        if (resolver->socket_fd_v4 >= 0) {
            FD_SET(resolver->socket_fd_v4, &read_fds);
            max_fd = resolver->socket_fd_v4;
        }
        if (resolver->socket_fd_v6 >= 0) {
            FD_SET(resolver->socket_fd_v6, &read_fds);
            if (resolver->socket_fd_v6 > max_fd) {
                max_fd = resolver->socket_fd_v6;
            }
        }
        
        struct timeval timeout = {0, 100000}; // 100ms
        int result = select(max_fd + 1, &read_fds, NULL, NULL, &timeout);
        
        if (result < 0) {
            if (errno != EINTR) {
                LOG_ERROR("DNS select error: %s", strerror(errno));
            }
            continue;
        }
        
        if (result > 0) {
            uint8_t buffer[512];
            struct sockaddr_storage src_addr;
            socklen_t addr_len = sizeof(src_addr);
            
            if (resolver->socket_fd_v4 >= 0 && FD_ISSET(resolver->socket_fd_v4, &read_fds)) {
                ssize_t bytes = recvfrom(resolver->socket_fd_v4, buffer, sizeof(buffer), 0,
                                       (struct sockaddr*)&src_addr, &addr_len);
                if (bytes > 0) {
                    struct sockaddr_in *sin = (struct sockaddr_in*)&src_addr;
                    ip_addr_t src_ip = { .v4.addr = sin->sin_addr.s_addr };
                    dns_resolver_process_packet(resolver, buffer, bytes, &src_ip, ntohs(sin->sin_port));
                }
            }
            
            if (resolver->socket_fd_v6 >= 0 && FD_ISSET(resolver->socket_fd_v6, &read_fds)) {
                ssize_t bytes = recvfrom(resolver->socket_fd_v6, buffer, sizeof(buffer), 0,
                                       (struct sockaddr*)&src_addr, &addr_len);
                if (bytes > 0) {
                    struct sockaddr_in6 *sin6 = (struct sockaddr_in6*)&src_addr;
                    ip_addr_t src_ip;
                    memcpy(src_ip.v6.addr, &sin6->sin6_addr, 16);
                    dns_resolver_process_packet(resolver, buffer, bytes, &src_ip, ntohs(sin6->sin6_port));
                }
            }
        }
        
        dns_resolver_process_timeouts(resolver);
    }
    
    LOG_DEBUG("DNS worker thread finished");
    return NULL;
}

static bool dns_send_query(dns_resolver_t *resolver, dns_query_t *query) {
    if (!resolver || !query || resolver->server_count == 0) return false;
    
    uint8_t packet[512];
    size_t packet_size = dns_build_query(query->hostname, query->type, query->transaction_id, 
                                        packet, sizeof(packet));
    if (packet_size == 0) return false;
    
    struct dns_server *server = &resolver->servers[query->retry_count % resolver->server_count];
    
    int sock_fd = (server->ip_version == 4) ? resolver->socket_fd_v4 : resolver->socket_fd_v6;
    if (sock_fd < 0) return false;
    
    ssize_t sent = 0;
    if (server->ip_version == 4) {
        struct sockaddr_in addr = {0};
        addr.sin_family = AF_INET;
        addr.sin_port = htons(server->port);
        addr.sin_addr.s_addr = server->addr.v4.addr;
        
        sent = sendto(sock_fd, packet, packet_size, 0, (struct sockaddr*)&addr, sizeof(addr));
    } else {
        struct sockaddr_in6 addr = {0};
        addr.sin6_family = AF_INET6;
        addr.sin6_port = htons(server->port);
        memcpy(&addr.sin6_addr, server->addr.v6.addr, 16);
        
        sent = sendto(sock_fd, packet, packet_size, 0, (struct sockaddr*)&addr, sizeof(addr));
    }
    
    if (sent < 0) {
        LOG_ERROR("Failed to send DNS query: %s", strerror(errno));
        resolver->stats_errors++;
        return false;
    }
    
    resolver->stats_queries_sent++;
    return true;
}

bool dns_resolver_process_packet(dns_resolver_t *resolver, const uint8_t *packet, size_t length, 
                                const ip_addr_t *src_addr, uint16_t src_port) {
    if (!resolver || !packet || length < DNS_HEADER_SIZE) return false;
    
    uint16_t transaction_id = (packet[0] << 8) | packet[1];
    
    pthread_mutex_lock(&resolver->mutex);
    
    dns_query_t *query = dns_find_query_by_id(resolver, transaction_id);
    if (!query) {
        LOG_DEBUG("Received DNS response for unknown transaction ID %d", transaction_id);
        pthread_mutex_unlock(&resolver->mutex);
        return false;
    }
    
    dns_response_t response = {0};
    if (!dns_parse_packet(packet, length, &response)) {
        LOG_ERROR("Failed to parse DNS response");
        resolver->stats_errors++;
        pthread_mutex_unlock(&resolver->mutex);
        return false;
    }
    
    resolver->stats_responses_received++;
    dns_complete_query(query, &response);
    
    pthread_mutex_unlock(&resolver->mutex);
    return true;
}

void dns_resolver_process_timeouts(dns_resolver_t *resolver) {
    if (!resolver) return;
    
    pthread_mutex_lock(&resolver->mutex);
    
    uint64_t current_time = clock_gettime_nsec_np(CLOCK_MONOTONIC);
    
    for (int i = 0; i < MAX_CONCURRENT_QUERIES; i++) {
        dns_query_t *query = &resolver->queries[i];
        if (!query->active || query->completed) continue;
        
        uint64_t elapsed_ms = (current_time - query->start_time_ns) / 1000000;
        
        if (elapsed_ms > query->timeout_ms) {
            if (query->retry_count < query->max_retries) {
                query->retry_count++;
                query->start_time_ns = current_time;
                
                if (!dns_send_query(resolver, query)) {
                    LOG_ERROR("Failed to retry DNS query for %s", query->hostname);
                    dns_complete_query(query, NULL);
                }
            } else {
                LOG_DEBUG("DNS query timeout for %s after %d retries", query->hostname, query->max_retries);
                resolver->stats_timeouts++;
                dns_complete_query(query, NULL);
            }
        }
    }
    
    pthread_mutex_unlock(&resolver->mutex);
}

static dns_query_t *dns_find_query_by_id(dns_resolver_t *resolver, uint16_t transaction_id) {
    for (int i = 0; i < MAX_CONCURRENT_QUERIES; i++) {
        dns_query_t *query = &resolver->queries[i];
        if (query->active && !query->completed && query->transaction_id == transaction_id) {
            return query;
        }
    }
    return NULL;
}

static void dns_complete_query(dns_query_t *query, dns_response_t *response) {
    if (!query) return;
    
    query->completed = true;
    
    if (query->callback) {
        query->callback(query, response, query->user_data);
    }
    
    query->active = false;
}

bool dns_is_valid_hostname(const char *hostname) {
    if (!hostname) return false;
    
    size_t len = strlen(hostname);
    if (len == 0 || len > DNS_MAX_NAME_LENGTH) return false;
    
    for (size_t i = 0; i < len; i++) {
        char c = hostname[i];
        if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || 
              (c >= '0' && c <= '9') || c == '.' || c == '-')) {
            return false;
        }
    }
    
    return true;
}

size_t dns_build_query(const char *hostname, dns_record_type_t type, uint16_t transaction_id, 
                      uint8_t *buffer, size_t buffer_size) {
    if (!hostname || !buffer) return 0;
    
    size_t hostname_len = strlen(hostname);
    if (hostname_len == 0 || hostname_len > DNS_MAX_NAME_LENGTH) return 0;
    
    // SECURITY FIX: Strict buffer size validation to prevent overflow
    size_t required_size = DNS_HEADER_SIZE + hostname_len + 2 + 4; // +2 for length encoding, +4 for type+class
    if (buffer_size < required_size) return 0;
    
    uint8_t *ptr = buffer;
    uint8_t *buffer_end = buffer + buffer_size;
    
    // Build header with bounds checking
    if (ptr + DNS_HEADER_SIZE > buffer_end) return 0;
    
    *(uint16_t*)ptr = htons(transaction_id); ptr += 2;
    *(uint16_t*)ptr = htons(0x0100); ptr += 2; // Standard query, recursion desired
    *(uint16_t*)ptr = htons(1); ptr += 2;      // 1 question
    *(uint16_t*)ptr = htons(0); ptr += 2;      // 0 answers
    *(uint16_t*)ptr = htons(0); ptr += 2;      // 0 authority
    *(uint16_t*)ptr = htons(0); ptr += 2;      // 0 additional
    
    // Build QNAME with strict bounds checking
    const char *label_start = hostname;
    const char *dot = strchr(hostname, '.');
    
    while (label_start && *label_start) {
        size_t label_len = dot ? (size_t)(dot - label_start) : strlen(label_start);
        
        // SECURITY FIX: Validate label length bounds
        if (label_len == 0 || label_len > DNS_MAX_LABEL_LENGTH) return 0;
        
        // Check buffer space for label length byte + label data
        if (ptr + 1 + label_len > buffer_end) return 0;
        
        *ptr++ = (uint8_t)label_len;
        memcpy(ptr, label_start, label_len);
        ptr += label_len;
        
        if (!dot) break;
        label_start = dot + 1;
        
        // Prevent infinite loop on malformed hostnames
        if (label_start >= hostname + hostname_len) break;
        
        dot = strchr(label_start, '.');
    }
    
    // Check space for null terminator + type + class
    if (ptr + 5 > buffer_end) return 0;
    
    *ptr++ = 0; // End of name
    
    *(uint16_t*)ptr = htons(type); ptr += 2;   // Query type
    *(uint16_t*)ptr = htons(1); ptr += 2;      // Query class (IN)
    
    return ptr - buffer;
}

bool dns_parse_packet(const uint8_t *packet, size_t length, dns_response_t *response) {
    if (!packet || length < DNS_HEADER_SIZE || !response) return false;
    
    memset(response, 0, sizeof(dns_response_t));
    
    const uint8_t *ptr = packet;
    
    response->transaction_id = ntohs(*(uint16_t*)ptr); ptr += 2;
    uint16_t flags = ntohs(*(uint16_t*)ptr); ptr += 2;
    response->question_count = ntohs(*(uint16_t*)ptr); ptr += 2;
    response->answer_count = ntohs(*(uint16_t*)ptr); ptr += 2;
    response->authority_count = ntohs(*(uint16_t*)ptr); ptr += 2;
    response->additional_count = ntohs(*(uint16_t*)ptr); ptr += 2;
    
    response->rcode = (dns_response_code_t)(flags & 0xF);
    response->authoritative = (flags & 0x400) != 0;
    response->truncated = (flags & 0x200) != 0;
    response->recursion_available = (flags & 0x80) != 0;
    response->timestamp_ns = clock_gettime_nsec_np(CLOCK_MONOTONIC);
    
    return true;
}

const char *dns_rcode_to_string(dns_response_code_t rcode) {
    switch (rcode) {
        case DNS_RCODE_NOERROR: return "No Error";
        case DNS_RCODE_FORMERR: return "Format Error";
        case DNS_RCODE_SERVFAIL: return "Server Failure";
        case DNS_RCODE_NXDOMAIN: return "Non-Existent Domain";
        case DNS_RCODE_NOTIMP: return "Not Implemented";
        case DNS_RCODE_REFUSED: return "Refused";
        default: return "Unknown";
    }
}

const char *dns_type_to_string(dns_record_type_t type) {
    switch (type) {
        case DNS_TYPE_A: return "A";
        case DNS_TYPE_AAAA: return "AAAA";
        case DNS_TYPE_CNAME: return "CNAME";
        case DNS_TYPE_MX: return "MX";
        case DNS_TYPE_TXT: return "TXT";
        case DNS_TYPE_PTR: return "PTR";
        default: return "Unknown";
    }
}

// PRODUCTION FIX: Add missing DNS resolver stats function
void dns_resolver_get_stats(dns_resolver_t *resolver, uint32_t *queries_sent, uint32_t *responses_received, 
                           uint32_t *timeouts, uint32_t *errors) {
    if (!resolver) {
        if (queries_sent) *queries_sent = 0;
        if (responses_received) *responses_received = 0;
        if (timeouts) *timeouts = 0;
        if (errors) *errors = 0;
        return;
    }
    
    pthread_mutex_lock(&resolver->mutex);
    
    if (queries_sent) *queries_sent = resolver->stats_queries_sent;
    if (responses_received) *responses_received = resolver->stats_responses_received;
    if (timeouts) *timeouts = resolver->stats_timeouts;
    if (errors) *errors = resolver->stats_errors;
    
    pthread_mutex_unlock(&resolver->mutex);
}