#ifndef RELATIVE_VPN_CONNECTION_MANAGER_H
#define RELATIVE_VPN_CONNECTION_MANAGER_H

#include "core/types.h"
#include <stdint.h>
#include <stdbool.h>

// Forward declare vpn_metrics_t to avoid circular dependencies
typedef struct vpn_metrics vpn_metrics_t;

typedef struct connection_manager connection_manager_t;
typedef struct tcp_connection tcp_connection_t;
typedef struct udp_session udp_session_t;

typedef enum connection_event {
    CONN_EVENT_ESTABLISHED,
    CONN_EVENT_DATA_RECEIVED,
    CONN_EVENT_DATA_SENT,
    CONN_EVENT_CLOSED,
    CONN_EVENT_ERROR,
    CONN_EVENT_TIMEOUT
} connection_event_t;

typedef void (*connection_callback_t)(tcp_connection_t *conn, connection_event_t event, void *data, size_t length, void *user_data);
typedef void (*udp_callback_t)(udp_session_t *session, const uint8_t *data, size_t length, const ip_addr_t *src_addr, uint16_t src_port, void *user_data);

connection_manager_t *connection_manager_create(void);
void connection_manager_destroy(connection_manager_t *manager);
void connection_manager_process_packet(connection_manager_t *manager, const packet_info_t *packet);
bool connection_manager_process_events(connection_manager_t *manager);

tcp_connection_t *tcp_connection_create(connection_manager_t *manager, const ip_addr_t *remote_addr, uint16_t remote_port, connection_callback_t callback, void *user_data);
void tcp_connection_destroy(tcp_connection_t *conn);
bool tcp_connection_send(tcp_connection_t *conn, const uint8_t *data, size_t length);
bool tcp_connection_close(tcp_connection_t *conn);
connection_state_t tcp_connection_get_state(tcp_connection_t *conn);
uint32_t tcp_connection_get_seq(tcp_connection_t *conn);
uint32_t tcp_connection_get_ack(tcp_connection_t *conn);

udp_session_t *udp_session_create(connection_manager_t *manager, uint16_t local_port, udp_callback_t callback, void *user_data);
void udp_session_destroy(udp_session_t *session);
bool udp_session_send(udp_session_t *session, const uint8_t *data, size_t length, const ip_addr_t *dest_addr, uint16_t dest_port);
uint16_t udp_session_get_port(udp_session_t *session);

size_t connection_manager_get_tcp_count(connection_manager_t *manager);
size_t connection_manager_get_udp_count(connection_manager_t *manager);
void connection_manager_get_stats(connection_manager_t *manager, vpn_metrics_t *metrics);

#endif