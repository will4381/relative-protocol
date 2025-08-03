#ifndef RELATIVE_VPN_UTUN_H
#define RELATIVE_VPN_UTUN_H

#include "core/types.h"
#include <stdint.h>
#include <stdbool.h>

typedef struct utun_handle utun_handle_t;

typedef void (*packet_received_callback_t)(const packet_info_t *packet, void *user_data);

utun_handle_t *utun_create(const char *interface_name, uint16_t mtu);
void utun_destroy(utun_handle_t *handle);
int utun_get_fd(utun_handle_t *handle);
const char *utun_get_name(utun_handle_t *handle);
uint16_t utun_get_mtu(utun_handle_t *handle);
bool utun_set_mtu(utun_handle_t *handle, uint16_t mtu);
ssize_t utun_read(utun_handle_t *handle, uint8_t *buffer, size_t buffer_size);
ssize_t utun_write(utun_handle_t *handle, const uint8_t *packet, size_t packet_size);
bool utun_start_read_loop(utun_handle_t *handle, packet_received_callback_t callback, void *user_data);
void utun_stop_read_loop(utun_handle_t *handle);

#endif