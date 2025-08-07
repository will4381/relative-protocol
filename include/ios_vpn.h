/**
 * iOS VPN Module - Clean, simple API for Swift integration
 * 
 * This module provides packet processing for iOS NetworkExtension VPNs.
 * It handles packet parsing, connection tracking, and header construction.
 */

#ifndef IOS_VPN_H
#define IOS_VPN_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include "core/types.h"

#ifdef __cplusplus
extern "C" {
#endif

// MARK: - Core Types

// flow_info_t and packet_info_t are now defined in core/types.h

typedef struct {
    uint8_t src_ip[16];  // IPv6 address
    uint8_t dst_ip[16];
    uint16_t src_port;
    uint16_t dst_port;
    uint8_t protocol;
} flow_info_v6_t;

typedef enum {
    PACKET_DIRECTION_OUTBOUND = 0,  // From device to internet
    PACKET_DIRECTION_INBOUND = 1    // From internet to device
} packet_direction_t;

// MARK: - Module Management

/**
 * Initialize the VPN module.
 * Call this once when starting the tunnel.
 */
bool ios_vpn_init(void);

/**
 * Cleanup the VPN module.
 * Call this when stopping the tunnel.
 */
void ios_vpn_cleanup(void);

// MARK: - Packet Processing

/**
 * Parse an IP packet to extract flow information.
 * 
 * @param packet_data Raw packet data
 * @param packet_length Length of packet
 * @param info Output: Parsed packet information
 * @return true if parsing succeeded
 */
bool ios_vpn_parse_packet(const uint8_t *packet_data, size_t packet_length, packet_info_t *info);

/**
 * Build a response packet with proper headers.
 * 
 * @param original_flow Flow info from original packet
 * @param response_data Response payload data
 * @param response_length Length of response payload
 * @param buffer Output buffer for complete packet
 * @param buffer_size Size of output buffer
 * @return Length of built packet, or 0 on error
 */
size_t ios_vpn_build_response_packet(
    const flow_info_t *original_flow,
    const uint8_t *response_data,
    size_t response_length,
    uint8_t *buffer,
    size_t buffer_size
);

// MARK: - Connection Tracking

typedef void* connection_handle_t;

/**
 * Track a new connection.
 * Returns a handle that can be used to find the connection later.
 */
connection_handle_t ios_vpn_track_connection(const flow_info_t *flow);

/**
 * Find a connection by destination endpoint.
 * Used to map responses back to original connections.
 */
connection_handle_t ios_vpn_find_connection(uint32_t dst_ip, uint16_t dst_port, uint8_t protocol);

/**
 * Get the original flow for a connection.
 * Used to build response packets with correct source/dest.
 */
bool ios_vpn_get_connection_flow(connection_handle_t handle, flow_info_t *flow);

/**
 * Remove a connection from tracking.
 */
void ios_vpn_remove_connection(connection_handle_t handle);

// MARK: - DNS Handling

/**
 * Check if a packet is a DNS query.
 */
bool ios_vpn_is_dns_packet(const packet_info_t *info);

/**
 * Process a DNS packet (optional caching, etc).
 * For now, just forwards to DNS servers.
 */
bool ios_vpn_process_dns(const uint8_t *packet_data, size_t packet_length);

// MARK: - IPv6/NAT64 Support

/**
 * Parse an IPv6 packet.
 */
bool ios_vpn_parse_packet_v6(const uint8_t *packet_data, size_t packet_length, flow_info_v6_t *flow);

/**
 * Check if NAT64 translation is needed.
 */
bool ios_vpn_needs_nat64(const flow_info_v6_t *flow);

/**
 * Translate IPv6 packet to IPv4 (for NAT64).
 */
size_t ios_vpn_translate_6to4(
    const uint8_t *ipv6_packet,
    size_t ipv6_length,
    uint8_t *ipv4_buffer,
    size_t buffer_size
);

// MARK: - Utilities

/**
 * Calculate IP checksum.
 */
uint16_t ios_vpn_ip_checksum(const uint8_t *data, size_t length);

/**
 * Calculate TCP/UDP checksum.
 */
uint16_t ios_vpn_transport_checksum(
    const uint8_t *data,
    size_t length,
    uint32_t src_ip,
    uint32_t dst_ip,
    uint8_t protocol
);

/**
 * Convert IP address to string for logging.
 */
const char* ios_vpn_ip_to_string(uint32_t ip);

/**
 * Get readable protocol name.
 */
const char* ios_vpn_protocol_name(uint8_t protocol);

// MARK: - Statistics

typedef struct {
    uint64_t packets_processed;
    uint64_t bytes_processed;
    uint32_t active_connections;
    uint32_t dns_queries;
    uint32_t nat64_translations;
} vpn_stats_t;

/**
 * Get current VPN statistics.
 */
void ios_vpn_get_stats(vpn_stats_t *stats);

#ifdef __cplusplus
}
#endif

#endif // IOS_VPN_H