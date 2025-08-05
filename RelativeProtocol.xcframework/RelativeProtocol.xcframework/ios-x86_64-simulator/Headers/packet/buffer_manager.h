#ifndef RELATIVE_VPN_BUFFER_MANAGER_H
#define RELATIVE_VPN_BUFFER_MANAGER_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdatomic.h>
#include <pthread.h>
#include <time.h>
#include "core/types.h"

#ifdef __cplusplus
extern "C" {
#endif

// PRODUCTION FIX: Safe packet buffer management system
typedef struct packet_buffer {
    uint8_t *data;                    // Actual packet data
    size_t length;                    // Current data length
    size_t capacity;                  // Buffer capacity
    atomic_int ref_count;             // Reference count for safe memory management
    bool owns_memory;                 // Whether this buffer owns the memory
    struct packet_buffer *next;       // For memory pool linked list
} packet_buffer_t;

typedef struct buffer_pool {
    packet_buffer_t *free_buffers;    // Free buffer list
    size_t buffer_size;               // Size of each buffer
    size_t total_buffers;             // Total buffers in pool
    size_t free_count;                // Number of free buffers
    pthread_mutex_t mutex;            // Protection for buffer pool
    atomic_ullong allocations;      // Allocation counter
    atomic_ullong deallocations;    // Deallocation counter
    
    // Dynamic resize support
    bool auto_resize_enabled;         // Enable automatic resizing
    float low_watermark;              // Grow when free% drops below this
    float high_watermark;             // Shrink when free% exceeds this
    size_t min_size;                  // Minimum pool size
    size_t max_size;                  // Maximum pool size
    time_t last_resize_time;          // Rate limit resizing
} buffer_pool_t;

typedef struct safe_packet {
    packet_buffer_t *buffer;          // Reference to managed buffer
    uint8_t *data;                    // Pointer to packet data (for convenience)
    size_t length;                    // Current packet length
    size_t max_length;                // Maximum allowed length
    flow_tuple_t flow;                // Flow information
    uint64_t timestamp_ns;            // Packet timestamp
} safe_packet_t;

// Buffer pool management
buffer_pool_t *buffer_pool_create(size_t buffer_size, size_t initial_count);
void buffer_pool_destroy(buffer_pool_t *pool);

// Buffer allocation/deallocation
packet_buffer_t *buffer_pool_acquire(buffer_pool_t *pool);
void buffer_pool_release(buffer_pool_t *pool, packet_buffer_t *buffer);

// Safe buffer operations
packet_buffer_t *packet_buffer_create(size_t capacity);
packet_buffer_t *packet_buffer_retain(packet_buffer_t *buffer);
void packet_buffer_release(packet_buffer_t *buffer);
bool packet_buffer_resize(packet_buffer_t *buffer, size_t new_capacity);
bool packet_buffer_copy_data(packet_buffer_t *buffer, const uint8_t *data, size_t length);

// Safe packet operations
safe_packet_t *safe_packet_create_from_buffer(packet_buffer_t *buffer, const flow_tuple_t *flow);
safe_packet_t *safe_packet_create_copy(const uint8_t *data, size_t length, const flow_tuple_t *flow);
void safe_packet_destroy(safe_packet_t *packet);
bool safe_packet_replace_data(safe_packet_t *packet, const uint8_t *new_data, size_t new_length);

// Utility functions
void buffer_pool_get_stats(buffer_pool_t *pool, size_t *total, size_t *free, uint64_t *allocs, uint64_t *deallocs);
bool packet_buffer_is_valid(const packet_buffer_t *buffer);

// Dynamic pool management
bool buffer_pool_resize(buffer_pool_t *pool, size_t new_size);
void buffer_pool_set_auto_resize(buffer_pool_t *pool, bool enabled);
void buffer_pool_set_resize_thresholds(buffer_pool_t *pool, float low_watermark, float high_watermark);

// Memory pool constants
#define SMALL_BUFFER_SIZE 1600    // Standard MTU + headers
#define LARGE_BUFFER_SIZE 9600    // Jumbo frame + headers
#define INITIAL_SMALL_BUFFERS 1000
#define INITIAL_LARGE_BUFFERS 100
#define MIN_POOL_SIZE 100         // Minimum buffers to maintain
#define MAX_POOL_SIZE 10000       // Maximum buffers allowed
#define DEFAULT_LOW_WATERMARK 0.2  // Grow pool when free buffers < 20%
#define DEFAULT_HIGH_WATERMARK 0.8 // Shrink pool when free buffers > 80%

#ifdef __cplusplus
}
#endif

#endif