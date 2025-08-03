#include "packet/buffer_manager.h"
#include "core/logging.h"
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <assert.h>

// PRODUCTION FIX: Thread-safe buffer pool implementation
buffer_pool_t *buffer_pool_create(size_t buffer_size, size_t initial_count) {
    if (buffer_size == 0 || initial_count == 0) {
        LOG_ERROR("Invalid buffer pool parameters: size=%zu, count=%zu", buffer_size, initial_count);
        return NULL;
    }
    
    buffer_pool_t *pool = calloc(1, sizeof(buffer_pool_t));
    if (!pool) {
        LOG_ERROR("Failed to allocate buffer pool");
        return NULL;
    }
    
    if (pthread_mutex_init(&pool->mutex, NULL) != 0) {
        LOG_ERROR("Failed to initialize buffer pool mutex");
        free(pool);
        return NULL;
    }
    
    pool->buffer_size = buffer_size;
    pool->total_buffers = initial_count;
    atomic_init(&pool->allocations, 0);
    atomic_init(&pool->deallocations, 0);
    
    // Pre-allocate buffers
    packet_buffer_t *prev = NULL;
    for (size_t i = 0; i < initial_count; i++) {
        packet_buffer_t *buffer = packet_buffer_create(buffer_size);
        if (!buffer) {
            LOG_ERROR("Failed to create buffer %zu/%zu in pool", i + 1, initial_count);
            buffer_pool_destroy(pool);
            return NULL;
        }
        
        buffer->next = prev;
        prev = buffer;
    }
    
    pool->free_buffers = prev;
    pool->free_count = initial_count;
    
    LOG_INFO("Created buffer pool: %zu buffers of %zu bytes each", initial_count, buffer_size);
    return pool;
}

void buffer_pool_destroy(buffer_pool_t *pool) {
    if (!pool) return;
    
    pthread_mutex_lock(&pool->mutex);
    
    // Free all buffers in the pool
    packet_buffer_t *current = pool->free_buffers;
    while (current) {
        packet_buffer_t *next = current->next;
        packet_buffer_release(current); // Will free if ref_count == 0
        current = next;
    }
    
    pthread_mutex_unlock(&pool->mutex);
    pthread_mutex_destroy(&pool->mutex);
    
    LOG_INFO("Destroyed buffer pool: %llu allocations, %llu deallocations", 
             atomic_load(&pool->allocations), atomic_load(&pool->deallocations));
    
    free(pool);
}

packet_buffer_t *buffer_pool_acquire(buffer_pool_t *pool) {
    if (!pool) return NULL;
    
    pthread_mutex_lock(&pool->mutex);
    
    packet_buffer_t *buffer = NULL;
    if (pool->free_buffers) {
        buffer = pool->free_buffers;
        pool->free_buffers = buffer->next;
        pool->free_count--;
        buffer->next = NULL;
        
        // Reset buffer state
        buffer->length = 0;
        atomic_store(&buffer->ref_count, 1);
    }
    
    pthread_mutex_unlock(&pool->mutex);
    
    if (buffer) {
        atomic_fetch_add(&pool->allocations, 1);
        LOG_TRACE("Acquired buffer from pool (free: %zu/%zu)", pool->free_count, pool->total_buffers);
    } else {
        // Pool is empty, create new buffer (with warning)
        LOG_WARN("Buffer pool exhausted, creating new buffer (consider increasing pool size)");
        buffer = packet_buffer_create(pool->buffer_size);
        if (buffer) {
            atomic_fetch_add(&pool->allocations, 1);
        }
    }
    
    return buffer;
}

void buffer_pool_release(buffer_pool_t *pool, packet_buffer_t *buffer) {
    if (!pool || !buffer) return;
    
    // Decrement reference count
    int old_ref = atomic_fetch_sub(&buffer->ref_count, 1);
    if (old_ref > 1) {
        // Buffer still has references, don't return to pool
        return;
    }
    
    // Clear sensitive data for security
    if (buffer->data && buffer->capacity > 0) {
        memset(buffer->data, 0, buffer->capacity);
    }
    
    pthread_mutex_lock(&pool->mutex);
    
    // Return buffer to pool if it's the right size
    if (buffer->capacity == pool->buffer_size && pool->free_count < pool->total_buffers) {
        buffer->next = pool->free_buffers;
        pool->free_buffers = buffer;
        pool->free_count++;
        atomic_fetch_add(&pool->deallocations, 1);
        
        pthread_mutex_unlock(&pool->mutex);
        LOG_TRACE("Returned buffer to pool (free: %zu/%zu)", pool->free_count, pool->total_buffers);
    } else {
        pthread_mutex_unlock(&pool->mutex);
        // Buffer doesn't fit in pool, free it
        packet_buffer_release(buffer);
        atomic_fetch_add(&pool->deallocations, 1);
    }
}

packet_buffer_t *packet_buffer_create(size_t capacity) {
    if (capacity == 0 || capacity > MAX_PACKET_SIZE * 2) {
        LOG_ERROR("Invalid buffer capacity: %zu", capacity);
        return NULL;
    }
    
    packet_buffer_t *buffer = calloc(1, sizeof(packet_buffer_t));
    if (!buffer) {
        LOG_ERROR("Failed to allocate packet buffer structure");
        return NULL;
    }
    
    buffer->data = malloc(capacity);
    if (!buffer->data) {
        LOG_ERROR("Failed to allocate packet buffer data (%zu bytes)", capacity);
        free(buffer);
        return NULL;
    }
    
    buffer->capacity = capacity;
    buffer->length = 0;
    buffer->owns_memory = true;
    atomic_init(&buffer->ref_count, 1);
    buffer->next = NULL;
    
    return buffer;
}

packet_buffer_t *packet_buffer_retain(packet_buffer_t *buffer) {
    if (!buffer) return NULL;
    
    atomic_fetch_add(&buffer->ref_count, 1);
    return buffer;
}

void packet_buffer_release(packet_buffer_t *buffer) {
    if (!buffer) return;
    
    int old_ref = atomic_fetch_sub(&buffer->ref_count, 1);
    if (old_ref == 1) {
        // Last reference, free the buffer
        if (buffer->owns_memory && buffer->data) {
            // Clear sensitive data before freeing
            memset(buffer->data, 0, buffer->capacity);
            free(buffer->data);
        }
        free(buffer);
    } else if (old_ref <= 0) {
        LOG_ERROR("packet_buffer_release: Buffer has invalid reference count");
    }
}

bool packet_buffer_resize(packet_buffer_t *buffer, size_t new_capacity) {
    if (!buffer || !buffer->owns_memory || new_capacity == 0 || new_capacity > MAX_PACKET_SIZE * 2) {
        return false;
    }
    
    if (atomic_load(&buffer->ref_count) > 1) {
        LOG_ERROR("Cannot resize buffer with multiple references");
        return false;
    }
    
    if (new_capacity <= buffer->capacity) {
        // Shrinking is always safe
        buffer->capacity = new_capacity;
        if (buffer->length > new_capacity) {
            buffer->length = new_capacity;
        }
        return true;
    }
    
    // Growing requires reallocation
    uint8_t *new_data = realloc(buffer->data, new_capacity);
    if (!new_data) {
        LOG_ERROR("Failed to resize buffer from %zu to %zu bytes", buffer->capacity, new_capacity);
        return false;
    }
    
    buffer->data = new_data;
    buffer->capacity = new_capacity;
    return true;
}

bool packet_buffer_copy_data(packet_buffer_t *buffer, const uint8_t *data, size_t length) {
    if (!buffer || !data || length == 0 || length > buffer->capacity) {
        return false;
    }
    
    memcpy(buffer->data, data, length);
    buffer->length = length;
    return true;
}

safe_packet_t *safe_packet_create_from_buffer(packet_buffer_t *buffer, const flow_tuple_t *flow) {
    if (!buffer || !flow) return NULL;
    
    safe_packet_t *packet = calloc(1, sizeof(safe_packet_t));
    if (!packet) {
        LOG_ERROR("Failed to allocate safe packet");
        return NULL;
    }
    
    packet->buffer = packet_buffer_retain(buffer);
    packet->data = buffer->data;
    packet->length = buffer->length;
    packet->max_length = buffer->capacity;
    packet->flow = *flow;
    packet->timestamp_ns = clock_gettime_nsec_np(CLOCK_MONOTONIC);
    
    return packet;
}

safe_packet_t *safe_packet_create_copy(const uint8_t *data, size_t length, const flow_tuple_t *flow) {
    if (!data || length == 0 || !flow) return NULL;
    
    packet_buffer_t *buffer = packet_buffer_create(length);
    if (!buffer) return NULL;
    
    if (!packet_buffer_copy_data(buffer, data, length)) {
        packet_buffer_release(buffer);
        return NULL;
    }
    
    safe_packet_t *packet = safe_packet_create_from_buffer(buffer, flow);
    packet_buffer_release(buffer); // safe_packet retains it
    
    return packet;
}

void safe_packet_destroy(safe_packet_t *packet) {
    if (!packet) return;
    
    if (packet->buffer) {
        packet_buffer_release(packet->buffer);
    }
    
    // Clear sensitive data
    memset(packet, 0, sizeof(safe_packet_t));
    free(packet);
}

bool safe_packet_replace_data(safe_packet_t *packet, const uint8_t *new_data, size_t new_length) {
    if (!packet || !packet->buffer || !new_data || new_length == 0) {
        return false;
    }
    
    if (new_length > packet->max_length) {
        // Need to resize buffer
        if (!packet_buffer_resize(packet->buffer, new_length)) {
            return false;
        }
        packet->max_length = packet->buffer->capacity;
    }
    
    if (!packet_buffer_copy_data(packet->buffer, new_data, new_length)) {
        return false;
    }
    
    packet->data = packet->buffer->data;
    packet->length = new_length;
    return true;
}

void buffer_pool_get_stats(buffer_pool_t *pool, size_t *total, size_t *free, uint64_t *allocs, uint64_t *deallocs) {
    if (!pool) return;
    
    pthread_mutex_lock(&pool->mutex);
    if (total) *total = pool->total_buffers;
    if (free) *free = pool->free_count;
    pthread_mutex_unlock(&pool->mutex);
    
    if (allocs) *allocs = atomic_load(&pool->allocations);
    if (deallocs) *deallocs = atomic_load(&pool->deallocations);
}

bool packet_buffer_is_valid(const packet_buffer_t *buffer) {
    if (!buffer) return false;
    if (!buffer->data && buffer->capacity > 0) return false;
    if (buffer->length > buffer->capacity) return false;
    if (atomic_load(&buffer->ref_count) <= 0) return false;
    return true;
}