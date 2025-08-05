#ifndef RELATIVE_VPN_SOCKET_BRIDGE_H
#define RELATIVE_VPN_SOCKET_BRIDGE_H

#include "core/types.h"
#include "tcp_udp/connection_manager.h"
#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct socket_bridge socket_bridge_t;
typedef struct bridge_connection bridge_connection_t;

typedef enum bridge_protocol {
    BRIDGE_TCP = 0,
    BRIDGE_UDP = 1
} bridge_protocol_t;

typedef void (*bridge_data_callback_t)(bridge_connection_t * _Nonnull conn, const uint8_t * _Nonnull data, size_t length, void * _Nullable user_data);
typedef void (*bridge_event_callback_t)(bridge_connection_t * _Nonnull conn, connection_event_t event, void * _Nullable user_data);

socket_bridge_t * _Nullable socket_bridge_create(connection_manager_t * _Nonnull conn_mgr);
void socket_bridge_destroy(socket_bridge_t * _Nullable bridge);

bridge_connection_t * _Nullable socket_bridge_create_tcp_connection(socket_bridge_t * _Nonnull bridge, 
                                                       const ip_addr_t * _Nonnull remote_addr, 
                                                       uint16_t remote_port,
                                                       bridge_data_callback_t _Nonnull data_callback,
                                                       bridge_event_callback_t _Nullable event_callback,
                                                       void * _Nullable user_data);

bridge_connection_t * _Nullable socket_bridge_create_udp_session(socket_bridge_t * _Nonnull bridge,
                                                     uint16_t local_port,
                                                     bridge_data_callback_t _Nonnull data_callback,
                                                     void * _Nullable user_data);

void socket_bridge_destroy_connection(bridge_connection_t * _Nullable conn);

bool socket_bridge_send_data(bridge_connection_t * _Nonnull conn, const uint8_t * _Nonnull data, size_t length);
bool socket_bridge_send_udp_data(bridge_connection_t * _Nonnull conn, const uint8_t * _Nonnull data, size_t length, 
                                const ip_addr_t * _Nonnull dest_addr, uint16_t dest_port);

void socket_bridge_process_packet(socket_bridge_t * _Nonnull bridge, const packet_info_t * _Nonnull packet);
bool socket_bridge_process_events(socket_bridge_t * _Nonnull bridge);

bridge_protocol_t bridge_connection_get_protocol(bridge_connection_t * _Nullable conn);
connection_state_t bridge_connection_get_state(bridge_connection_t * _Nullable conn);
uint16_t bridge_connection_get_local_port(bridge_connection_t * _Nullable conn);
uint16_t bridge_connection_get_remote_port(bridge_connection_t * _Nullable conn);
const ip_addr_t * _Nullable bridge_connection_get_remote_addr(bridge_connection_t * _Nullable conn);

size_t socket_bridge_get_connection_count(socket_bridge_t * _Nonnull bridge);
void socket_bridge_get_stats(socket_bridge_t * _Nonnull bridge, vpn_metrics_t * _Nonnull metrics);

#if defined(TARGET_OS_IOS) && defined(__OBJC__)
#import <NetworkExtension/NetworkExtension.h>
#import <Network/Network.h>

typedef void (^tcp_completion_handler_t)(nw_connection_t _Nullable connection);
typedef void (^udp_completion_handler_t)(nw_connection_t _Nullable session);

bool socket_bridge_create_tcp_connection_ios(socket_bridge_t * _Nonnull bridge,
                                           NEPacketTunnelProvider * _Nonnull provider,
                                           const char * _Nonnull hostname,
                                           uint16_t port,
                                           tcp_completion_handler_t _Nonnull completion);

bool socket_bridge_create_udp_session_ios(socket_bridge_t * _Nonnull bridge,
                                        NEPacketTunnelProvider * _Nonnull provider,
                                        const char * _Nonnull hostname,
                                        uint16_t port,
                                        udp_completion_handler_t _Nonnull completion);
#endif

#ifdef __cplusplus
}
#endif

#endif