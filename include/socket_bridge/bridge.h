#ifndef RELATIVE_VPN_SOCKET_BRIDGE_H
#define RELATIVE_VPN_SOCKET_BRIDGE_H

#include "core/types.h"
#include "tcp_udp/connection_manager.h"
#include <stdint.h>
#include <stdbool.h>

typedef struct socket_bridge socket_bridge_t;
typedef struct bridge_connection bridge_connection_t;

typedef enum bridge_protocol {
    BRIDGE_TCP = 0,
    BRIDGE_UDP = 1
} bridge_protocol_t;

typedef void (*bridge_data_callback_t)(bridge_connection_t *conn, const uint8_t *data, size_t length, void *user_data);
typedef void (*bridge_event_callback_t)(bridge_connection_t *conn, connection_event_t event, void *user_data);

socket_bridge_t *socket_bridge_create(connection_manager_t *conn_mgr);
void socket_bridge_destroy(socket_bridge_t *bridge);

bridge_connection_t *socket_bridge_create_tcp_connection(socket_bridge_t *bridge, 
                                                       const ip_addr_t *remote_addr, 
                                                       uint16_t remote_port,
                                                       bridge_data_callback_t data_callback,
                                                       bridge_event_callback_t event_callback,
                                                       void *user_data);

bridge_connection_t *socket_bridge_create_udp_session(socket_bridge_t *bridge,
                                                     uint16_t local_port,
                                                     bridge_data_callback_t data_callback,
                                                     void *user_data);

void socket_bridge_destroy_connection(bridge_connection_t *conn);

bool socket_bridge_send_data(bridge_connection_t *conn, const uint8_t *data, size_t length);
bool socket_bridge_send_udp_data(bridge_connection_t *conn, const uint8_t *data, size_t length, 
                                const ip_addr_t *dest_addr, uint16_t dest_port);

void socket_bridge_process_packet(socket_bridge_t *bridge, const packet_info_t *packet);
bool socket_bridge_process_events(socket_bridge_t *bridge);

bridge_protocol_t bridge_connection_get_protocol(bridge_connection_t *conn);
connection_state_t bridge_connection_get_state(bridge_connection_t *conn);
uint16_t bridge_connection_get_local_port(bridge_connection_t *conn);
uint16_t bridge_connection_get_remote_port(bridge_connection_t *conn);
const ip_addr_t *bridge_connection_get_remote_addr(bridge_connection_t *conn);

size_t socket_bridge_get_connection_count(socket_bridge_t *bridge);
void socket_bridge_get_stats(socket_bridge_t *bridge, vpn_metrics_t *metrics);

#ifdef TARGET_OS_IOS
#import <NetworkExtension/NetworkExtension.h>

typedef void (^tcp_completion_handler_t)(NWTCPConnection * _Nullable connection);
typedef void (^udp_completion_handler_t)(NWUDPSession * _Nullable session);

bool socket_bridge_create_tcp_connection_ios(socket_bridge_t *bridge,
                                           NEPacketTunnelProvider *provider,
                                           const char *hostname,
                                           uint16_t port,
                                           tcp_completion_handler_t completion);

bool socket_bridge_create_udp_session_ios(socket_bridge_t *bridge,
                                        NEPacketTunnelProvider *provider,
                                        const char *hostname,
                                        uint16_t port,
                                        udp_completion_handler_t completion);
#endif

#endif