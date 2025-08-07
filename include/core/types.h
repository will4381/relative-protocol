#ifndef RELATIVE_VPN_TYPES_H
#define RELATIVE_VPN_TYPES_H

#include <stdint.h>
#include <stdbool.h>
#include <netinet/in.h>

#ifdef __cplusplus
extern "C" {
#endif

#define MAX_PACKET_SIZE 65535
#define MAX_MTU 1500
#define MIN_MTU 576
#define DNS_CACHE_DEFAULT_SIZE 1024
#define METRICS_BUFFER_DEFAULT_SIZE 4096

typedef struct ipv4_addr {
    uint32_t addr;
} ipv4_addr_t;

typedef struct ipv6_addr {
    uint8_t addr[16];
} ipv6_addr_t;

typedef union ip_addr {
    ipv4_addr_t v4;
    ipv6_addr_t v6;
} ip_addr_t;

// Use ios_vpn.h types for consistency
// Legacy flow_tuple_t is now an alias to flow_info_t
typedef struct {
    uint32_t src_ip;    // Direct IPv4 address (network byte order)
    uint32_t dst_ip;    // Direct IPv4 address (network byte order)
    uint16_t src_port;
    uint16_t dst_port;
    uint8_t protocol;   // 6=TCP, 17=UDP
    uint8_t ip_version; // 4 or 6
} flow_tuple_t;

// Legacy alias - use flow_info_t from ios_vpn.h instead
typedef flow_tuple_t flow_info_t;

// Packet info with payload details
typedef struct {
    flow_info_t flow;
    const uint8_t *payload;
    size_t payload_length;
    size_t header_length;
    uint16_t length;        // Total packet length (for backwards compatibility)
    uint64_t timestamp_ns;  // Timestamp (for backwards compatibility)
    uint8_t *data;         // Raw data pointer (for backwards compatibility)
} packet_info_t;

typedef enum protocol_type {
    PROTO_ICMP = 1,
    PROTO_TCP = 6,
    PROTO_UDP = 17,
    PROTO_ICMPV6 = 58
} protocol_type_t;

typedef enum connection_state {
    CONN_CLOSED = 0,
    CONN_SYN_SENT,
    CONN_SYN_RECV,
    CONN_ESTABLISHED,
    CONN_FIN_WAIT1,
    CONN_FIN_WAIT2,
    CONN_CLOSE_WAIT,
    CONN_CLOSING,
    CONN_LAST_ACK,
    CONN_TIME_WAIT
} connection_state_t;

#ifdef __cplusplus
}
#endif

#endif