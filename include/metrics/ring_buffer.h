#ifndef RELATIVE_VPN_RING_BUFFER_H
#define RELATIVE_VPN_RING_BUFFER_H

#include <stdint.h>
#include <stdbool.h>
#include <stdatomic.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct ring_buffer ring_buffer_t;

typedef struct flow_metrics {
    uint64_t src_ip[2];
    uint64_t dst_ip[2];
    uint16_t src_port;
    uint16_t dst_port;
    uint8_t protocol;
    uint8_t ip_version;
    uint64_t bytes_in;
    uint64_t bytes_out;
    uint32_t packets_in;
    uint32_t packets_out;
    uint64_t start_time_ns;
    uint64_t last_activity_ns;
} flow_metrics_t;

ring_buffer_t *ring_buffer_create(size_t capacity);
void ring_buffer_destroy(ring_buffer_t *rb);
bool ring_buffer_push(ring_buffer_t *rb, const flow_metrics_t *metrics);
bool ring_buffer_pop(ring_buffer_t *rb, flow_metrics_t *metrics);
size_t ring_buffer_size(ring_buffer_t *rb);
size_t ring_buffer_capacity(ring_buffer_t *rb);
bool ring_buffer_is_empty(ring_buffer_t *rb);
bool ring_buffer_is_full(ring_buffer_t *rb);
void ring_buffer_clear(ring_buffer_t *rb);
size_t ring_buffer_get_size(ring_buffer_t *rb);
size_t ring_buffer_get_count(ring_buffer_t *rb);

#ifdef __cplusplus
}
#endif

#endif