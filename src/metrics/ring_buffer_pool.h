#ifndef RING_BUFFER_POOL_H
#define RING_BUFFER_POOL_H

#include "ring_buffer.h"
#include <stdatomic.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Memory pool for ring buffer allocations to reduce heap fragmentation
 * and improve memory cleanup behavior on macOS.
 */

typedef struct ring_buffer_pool ring_buffer_pool_t;

/**
 * Create a memory pool for ring buffers with specific capacity
 * @param buffer_capacity Capacity of each ring buffer in the pool
 * @param pool_size Maximum number of buffers to keep in pool
 * @return Pool instance or NULL on failure
 */
ring_buffer_pool_t* ring_buffer_pool_create(size_t buffer_capacity, size_t pool_size);

/**
 * Destroy memory pool and all cached buffers
 */
void ring_buffer_pool_destroy(ring_buffer_pool_t* pool);

/**
 * Get ring buffer from pool (creates new if pool empty)
 * @param pool Pool instance
 * @return Ring buffer instance or NULL on failure
 */
ring_buffer_t* ring_buffer_pool_acquire(ring_buffer_pool_t* pool);

/**
 * Return ring buffer to pool for reuse
 * @param pool Pool instance
 * @param buffer Buffer to return (will be cleared)
 * @return true if returned to pool, false if pool full (buffer destroyed)
 */
bool ring_buffer_pool_release(ring_buffer_pool_t* pool, ring_buffer_t* buffer);

/**
 * Get pool statistics
 */
typedef struct {
    size_t total_created;
    size_t currently_pooled;
    size_t cache_hits;
    size_t cache_misses;
} ring_buffer_pool_stats_t;

void ring_buffer_pool_get_stats(ring_buffer_pool_t* pool, ring_buffer_pool_stats_t* stats);

/**
 * Global pool for standard capacity buffers (10,000 elements)
 * This reduces memory fragmentation for common use cases
 */
ring_buffer_t* ring_buffer_create_pooled(size_t capacity);
void ring_buffer_destroy_pooled(ring_buffer_t* buffer);

#ifdef __cplusplus
}
#endif

#endif // RING_BUFFER_POOL_H