# RelativeProtocol API Reference

Complete API documentation for the RelativeProtocol VPN framework.

## Table of Contents

- [Core VPN APIs](#core-vpn-apis)
- [Configuration Structures](#configuration-structures)
- [Status and Metrics](#status-and-metrics)
- [DNS Management](#dns-management)
- [Socket Bridge](#socket-bridge)
- [Privacy Guards](#privacy-guards)
- [Packet Management](#packet-management)
- [Connection Management](#connection-management)
- [Error Codes](#error-codes)
- [Logging](#logging)

## Core VPN APIs

### `relative_vpn_create`

Creates a new VPN instance with the specified configuration.

```c
relative_vpn_t* _Nullable relative_vpn_create(const vpn_config_t* _Nonnull config);
```

**Parameters:**
- `config`: Pointer to VPN configuration structure (must not be NULL)

**Returns:**
- Valid pointer to VPN instance on success
- NULL on failure (invalid config, memory allocation failure)

**Thread Safety:** Safe to call from any thread

**Memory Management:** Caller must call `relative_vpn_destroy()` when done

**Example:**
```c
vpn_config_t config = {
    .server_address = "vpn.example.com",
    .server_port = 443,
    .enable_dns_cache = true
};
relative_vpn_t* vpn = relative_vpn_create(&config);
```

### `relative_vpn_start`

Starts the VPN connection.

```c
vpn_error_t relative_vpn_start(relative_vpn_t* _Nonnull vpn);
```

**Parameters:**
- `vpn`: Valid VPN instance

**Returns:**
- `VPN_SUCCESS` (0) on success
- Error code on failure

### `relative_vpn_stop`

Stops the VPN connection gracefully.

```c
vpn_error_t relative_vpn_stop(relative_vpn_t* _Nonnull vpn);
```

**Parameters:**
- `vpn`: Valid VPN instance

**Returns:**
- `VPN_SUCCESS` (0) on success
- Error code on failure

### `relative_vpn_destroy`

Destroys the VPN instance and frees all resources.

```c
void relative_vpn_destroy(relative_vpn_t* _Nullable vpn);
```

**Parameters:**
- `vpn`: VPN instance to destroy (can be NULL)

**Notes:**
- Always call this when done with VPN instance
- Automatically stops connection if still active
- Safe to call with NULL

## Configuration Structures

### `vpn_config_t`

Main VPN configuration structure.

```c
typedef struct vpn_config {
    char server_address[256];      // Server hostname or IP
    uint16_t server_port;          // Server port (default: 443)
    char auth_token[512];          // Authentication token
    uint32_t max_retries;          // Max connection retries
    uint32_t timeout_ms;           // Connection timeout in milliseconds
    bool enable_dns_cache;         // Enable DNS caching
    bool enable_privacy_guards;    // Enable privacy protection
    uint32_t dns_cache_size;       // DNS cache entries (default: 1000)
    uint32_t metrics_buffer_size;  // Metrics buffer size (default: 100)
} vpn_config_t;
```

### `dns_config_t`

DNS configuration structure.

```c
typedef struct dns_config {
    char primary_server[256];      // Primary DNS server
    char secondary_server[256];    // Secondary DNS server
    uint32_t cache_size;          // Cache size in entries
    uint32_t ttl_seconds;         // Default TTL in seconds
    bool enable_dnssec;           // Enable DNSSEC validation
    bool enable_dot;              // Enable DNS over TLS
} dns_config_t;
```

## Status and Metrics

### `relative_vpn_get_status`

Gets the current VPN connection status.

```c
vpn_status_t relative_vpn_get_status(relative_vpn_t* _Nonnull vpn);
```

**Status Values:**
```c
typedef enum {
    VPN_STATUS_DISCONNECTED = 0,
    VPN_STATUS_CONNECTING = 1,
    VPN_STATUS_CONNECTED = 2,
    VPN_STATUS_DISCONNECTING = 3,
    VPN_STATUS_RECONNECTING = 4,
    VPN_STATUS_ERROR = -1
} vpn_status_t;
```

### `relative_vpn_get_metrics`

Retrieves connection metrics.

```c
void relative_vpn_get_metrics(
    relative_vpn_t* _Nonnull vpn, 
    vpn_metrics_t* _Nonnull metrics
);
```

**Metrics Structure:**
```c
typedef struct vpn_metrics {
    uint64_t bytes_sent;              // Total bytes sent
    uint64_t bytes_received;          // Total bytes received
    uint64_t packets_sent;            // Total packets sent
    uint64_t packets_received;        // Total packets received
    uint64_t connection_duration_seconds; // Connection duration
    uint32_t current_mtu;             // Current MTU size
    uint32_t optimal_mtu;             // Discovered optimal MTU
    int32_t last_error_code;          // Last error code
    uint32_t reconnect_count;         // Number of reconnections
    double average_latency_ms;        // Average latency
} vpn_metrics_t;
```

## DNS Management

### `dns_resolver_create`

Creates a DNS resolver instance.

```c
dns_resolver_t* _Nullable dns_resolver_create(dns_config_t* _Nonnull config);
```

### `dns_resolve`

Resolves a hostname to IP address.

```c
int dns_resolve(
    dns_resolver_t* _Nonnull resolver,
    const char* _Nonnull hostname,
    char* _Nonnull ip_buffer,
    size_t buffer_size
);
```

**Parameters:**
- `resolver`: DNS resolver instance
- `hostname`: Hostname to resolve
- `ip_buffer`: Buffer to store resolved IP
- `buffer_size`: Size of IP buffer

**Returns:**
- 0 on success
- -1 on failure

### `dns_cache_get`

Retrieves cached DNS entry.

```c
bool dns_cache_get(
    dns_cache_t* _Nonnull cache,
    const char* _Nonnull hostname,
    dns_entry_t* _Nonnull entry
);
```

### `dns_cache_stats`

Gets DNS cache statistics.

```c
typedef struct dns_cache_stats {
    uint32_t total_entries;    // Total cached entries
    uint32_t cache_hits;       // Number of cache hits
    uint32_t cache_misses;     // Number of cache misses
    uint32_t evictions;        // Number of evictions
    double hit_rate;           // Cache hit rate percentage
} dns_cache_stats_t;

void dns_cache_get_stats(
    dns_cache_t* _Nonnull cache,
    dns_cache_stats_t* _Nonnull stats
);
```

## Socket Bridge

### `socket_bridge_create`

Creates a socket bridge for iOS NetworkExtension.

```c
socket_bridge_t* _Nullable socket_bridge_create(
    connection_manager_t* _Nonnull conn_mgr
);
```

### `socket_bridge_send_data`

Sends data through the socket bridge.

```c
bool socket_bridge_send_data(
    bridge_connection_t* _Nonnull conn,
    const uint8_t* _Nonnull data,
    size_t length
);
```

### `socket_bridge_receive_data`

Receives data from the socket bridge.

```c
ssize_t socket_bridge_receive_data(
    bridge_connection_t* _Nonnull conn,
    uint8_t* _Nonnull buffer,
    size_t buffer_size
);
```

**Returns:**
- Number of bytes received on success
- -1 on error
- 0 on connection closed

## Privacy Guards

### `privacy_guards_create`

Creates privacy guards instance.

```c
privacy_guards_t* _Nullable privacy_guards_create(void);
```

### `privacy_guards_check_dns_leak`

Checks for DNS leaks.

```c
bool privacy_guards_check_dns_leak(
    privacy_guards_t* _Nonnull guards,
    const char* _Nonnull dns_server
);
```

**Returns:**
- true if DNS leak detected
- false if safe

### `privacy_guards_validate_tls`

Validates TLS certificate.

```c
typedef struct tls_validation_result {
    bool is_valid;
    bool has_valid_chain;
    bool hostname_matches;
    char issuer[256];
    char subject[256];
    time_t expiry_time;
} tls_validation_result_t;

bool privacy_guards_validate_tls(
    privacy_guards_t* _Nonnull guards,
    const uint8_t* _Nonnull cert_data,
    size_t cert_length,
    const char* _Nonnull hostname,
    tls_validation_result_t* _Nonnull result
);
```

### `privacy_guards_get_violations`

Gets privacy violations.

```c
typedef struct privacy_violation {
    privacy_violation_type_t type;
    time_t timestamp;
    char details[512];
    char type_string[64];
} privacy_violation_t;

typedef enum {
    VIOLATION_DNS_LEAK = 1,
    VIOLATION_IP_LEAK = 2,
    VIOLATION_WEBRTC_LEAK = 3,
    VIOLATION_TLS_ISSUE = 4,
    VIOLATION_PROTOCOL_DOWNGRADE = 5
} privacy_violation_type_t;

size_t privacy_guards_get_violations(
    privacy_guards_t* _Nonnull guards,
    privacy_violation_t* _Nonnull buffer,
    size_t buffer_count
);
```

## Packet Management

### `buffer_manager_create`

Creates a packet buffer manager.

```c
buffer_manager_t* _Nullable buffer_manager_create(size_t pool_size);
```

### `buffer_manager_allocate`

Allocates a packet buffer.

```c
packet_buffer_t* _Nullable buffer_manager_allocate(
    buffer_manager_t* _Nonnull manager,
    size_t size
);
```

### `buffer_manager_release`

Releases a packet buffer back to the pool.

```c
void buffer_manager_release(
    buffer_manager_t* _Nonnull manager,
    packet_buffer_t* _Nonnull buffer
);
```

### `packet_tunnel_provider_handle_packet`

Processes incoming packet from iOS NetworkExtension.

```c
typedef struct packet {
    uint8_t* data;
    size_t length;
    uint8_t protocol_family;  // AF_INET or AF_INET6
} packet_t;

void packet_tunnel_provider_handle_packet(
    void* _Nonnull provider,
    packet_t* _Nonnull packet
);
```

## Connection Management

### `connection_manager_create`

Creates a connection manager.

```c
connection_manager_t* _Nullable connection_manager_create(
    size_t max_connections
);
```

### `connection_manager_add`

Adds a new connection.

```c
typedef struct connection_info {
    char remote_address[256];
    uint16_t remote_port;
    char local_address[256];
    uint16_t local_port;
    connection_protocol_t protocol;  // TCP or UDP
} connection_info_t;

connection_id_t connection_manager_add(
    connection_manager_t* _Nonnull manager,
    connection_info_t* _Nonnull info
);
```

### `connection_manager_remove`

Removes a connection.

```c
bool connection_manager_remove(
    connection_manager_t* _Nonnull manager,
    connection_id_t conn_id
);
```

### `connection_manager_get_stats`

Gets connection statistics.

```c
typedef struct connection_stats {
    size_t active_connections;
    size_t total_connections;
    size_t failed_connections;
    uint64_t total_bytes_sent;
    uint64_t total_bytes_received;
} connection_stats_t;

void connection_manager_get_stats(
    connection_manager_t* _Nonnull manager,
    connection_stats_t* _Nonnull stats
);
```

## Error Codes

```c
typedef enum {
    VPN_SUCCESS = 0,
    VPN_ERROR_INVALID_CONFIG = -1,
    VPN_ERROR_CONNECTION_FAILED = -2,
    VPN_ERROR_AUTH_FAILED = -3,
    VPN_ERROR_TIMEOUT = -4,
    VPN_ERROR_MEMORY = -5,
    VPN_ERROR_NETWORK = -6,
    VPN_ERROR_NOT_CONNECTED = -7,
    VPN_ERROR_ALREADY_CONNECTED = -8,
    VPN_ERROR_PERMISSION_DENIED = -9,
    VPN_ERROR_PROTOCOL = -10,
    VPN_ERROR_SERVER_UNREACHABLE = -11,
    VPN_ERROR_CERTIFICATE = -12,
    VPN_ERROR_DNS_RESOLUTION = -13,
    VPN_ERROR_PRIVACY_VIOLATION = -14,
    VPN_ERROR_RATE_LIMITED = -15,
    VPN_ERROR_MAINTENANCE = -16,
    VPN_ERROR_INCOMPATIBLE_VERSION = -17,
    VPN_ERROR_INTERNAL = -99
} vpn_error_t;

// Get human-readable error message
const char* _Nonnull vpn_error_string(vpn_error_t error);

// Get detailed error information
typedef struct vpn_error_info {
    vpn_error_t code;
    char message[256];
    char details[512];
    uint64_t timestamp;
    bool is_recoverable;
} vpn_error_info_t;

void vpn_get_last_error(
    relative_vpn_t* _Nonnull vpn,
    vpn_error_info_t* _Nonnull error_info
);
```

## Logging

### `log_set_level`

Sets the logging level.

```c
typedef enum {
    LOG_LEVEL_NONE = 0,
    LOG_LEVEL_ERROR = 1,
    LOG_LEVEL_WARN = 2,
    LOG_LEVEL_INFO = 3,
    LOG_LEVEL_DEBUG = 4
} log_level_t;

void log_set_level(log_level_t level);
```

### `log_set_handler`

Sets custom log handler.

```c
typedef void (*log_handler_t)(
    log_level_t level,
    const char* _Nonnull message
);

void log_set_handler(log_handler_t _Nullable handler);
```

**Example:**
```c
void custom_log_handler(log_level_t level, const char* message) {
    NSLog(@"[RelativeVPN][%d] %s", level, message);
}

log_set_handler(custom_log_handler);
log_set_level(LOG_LEVEL_DEBUG);
```

## Advanced Features

### MTU Discovery

```c
// Enable MTU discovery
void relative_vpn_enable_mtu_discovery(
    relative_vpn_t* _Nonnull vpn,
    bool enable
);

// Get optimal MTU
uint32_t relative_vpn_get_optimal_mtu(relative_vpn_t* _Nonnull vpn);
```

### NAT64 Translation

```c
// Enable NAT64 for IPv6-only networks
void relative_vpn_enable_nat64(
    relative_vpn_t* _Nonnull vpn,
    bool enable
);

// Check if NAT64 is active
bool relative_vpn_is_nat64_active(relative_vpn_t* _Nonnull vpn);
```

### TLS/QUIC Classification

```c
// Check if packet is TLS
bool classifier_is_tls(const uint8_t* _Nonnull data, size_t length);

// Check if packet is QUIC
bool classifier_is_quic(const uint8_t* _Nonnull data, size_t length);

// Get protocol info
typedef struct protocol_info {
    bool is_encrypted;
    char protocol_name[64];
    uint16_t version;
} protocol_info_t;

bool classifier_get_protocol_info(
    const uint8_t* _Nonnull data,
    size_t length,
    protocol_info_t* _Nonnull info
);
```

### Crash Reporting

```c
// Set crash handler
typedef void (*crash_handler_t)(const char* _Nonnull report);
void crash_reporter_set_handler(crash_handler_t _Nullable handler);

// Generate crash report
void crash_reporter_generate_report(char* _Nonnull buffer, size_t size);
```

## Thread Safety

All APIs are thread-safe unless otherwise noted. The framework uses internal locking to ensure safe concurrent access. However, for best performance:

1. Create VPN instances on the main thread
2. Use a dedicated queue for packet processing
3. Avoid holding references across thread boundaries
4. Use atomic operations for status checks

## Memory Management

The framework follows these memory management rules:

1. **Ownership**: Functions that return pointers transfer ownership unless noted
2. **Cleanup**: Always call corresponding destroy functions
3. **Nullability**: All pointers are annotated with `_Nullable` or `_Nonnull`
4. **Buffer Management**: Use the buffer manager for packet allocation

## Best Practices

1. **Error Handling**: Always check return values
2. **Resource Cleanup**: Use RAII patterns or defer statements
3. **Configuration Validation**: Validate config before creating VPN
4. **Logging**: Set appropriate log levels for production
5. **Privacy**: Enable privacy guards for production builds
6. **Performance**: Use buffer pools for packet processing