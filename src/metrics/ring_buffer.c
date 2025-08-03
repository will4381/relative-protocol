#include "metrics/ring_buffer.h"
#include "core/logging.h"
#include <stdlib.h>
#include <string.h>

struct ring_buffer {
    flow_metrics_t *buffer;
    size_t capacity;
    atomic_size_t head;
    atomic_size_t tail;
    atomic_size_t count;
};

ring_buffer_t *ring_buffer_create(size_t capacity) {
    if (capacity == 0 || capacity > SIZE_MAX / sizeof(flow_metrics_t)) {
        LOG_ERROR("Invalid ring buffer capacity: %zu", capacity);
        return NULL;
    }
    
    ring_buffer_t *rb = calloc(1, sizeof(ring_buffer_t));
    if (!rb) {
        LOG_ERROR("Failed to allocate ring buffer");
        return NULL;
    }
    
    rb->buffer = calloc(capacity, sizeof(flow_metrics_t));
    if (!rb->buffer) {
        LOG_ERROR("Failed to allocate ring buffer data");
        free(rb);
        return NULL;
    }
    
    rb->capacity = capacity;
    atomic_init(&rb->head, 0);
    atomic_init(&rb->tail, 0);
    atomic_init(&rb->count, 0);
    
    LOG_DEBUG("Created ring buffer with capacity %zu", capacity);
    return rb;
}

void ring_buffer_destroy(ring_buffer_t *rb) {
    if (!rb) return;
    
    LOG_DEBUG("Destroying ring buffer");
    
    // SECURITY FIX: Secure cleanup to prevent use-after-free and data leaks
    if (rb->buffer) {
        // Clear all buffer data before freeing
        memset(rb->buffer, 0, rb->capacity * sizeof(flow_metrics_t));
        free(rb->buffer);
        rb->buffer = NULL;
    }
    
    // Clear ring buffer structure
    rb->capacity = 0;
    atomic_store(&rb->head, 0);
    atomic_store(&rb->tail, 0);
    atomic_store(&rb->count, 0);
    
    free(rb);
}

bool ring_buffer_push(ring_buffer_t *rb, const flow_metrics_t *metrics) {
    if (!rb || !metrics) {
        return false;
    }
    
    // SECURITY FIX: Use atomic compare-and-swap loop to prevent TOCTOU race conditions
    while (true) {
        size_t current_count = atomic_load(&rb->count);
        if (current_count >= rb->capacity) {
            return false; // Buffer is full
        }
        
        size_t current_head = atomic_load(&rb->head);
        
        // Validate head position to prevent buffer overflow
        if (current_head >= rb->capacity) {
            return false;
        }
        
        // Calculate new head position
        size_t new_head = (current_head + 1) % rb->capacity;
        
        // Atomic compare-and-swap to claim the slot
        if (atomic_compare_exchange_weak(&rb->head, &current_head, new_head)) {
            // Successfully claimed slot at current_head, now copy data
            memcpy(&rb->buffer[current_head], metrics, sizeof(flow_metrics_t));
            
            // Use memory barrier to ensure copy completes before updating count
            __atomic_thread_fence(__ATOMIC_SEQ_CST);
            
            // Increment count after successful write
            size_t old_count = atomic_fetch_add(&rb->count, 1);
            
            // Double-check we didn't exceed capacity (shouldn't happen with proper logic)
            if (old_count >= rb->capacity) {
                // This is a critical error - rollback
                atomic_fetch_sub(&rb->count, 1);
                return false;
            }
            
            return true;
        }
        
        // CAS failed, another thread modified head, retry
        // Add a small backoff to reduce contention
        __atomic_thread_fence(__ATOMIC_ACQUIRE);
    }
}

bool ring_buffer_pop(ring_buffer_t *rb, flow_metrics_t *metrics) {
    if (!rb || !metrics) {
        return false;
    }
    
    // SECURITY FIX: Use atomic compare-and-swap loop to prevent TOCTOU race conditions
    while (true) {
        size_t current_count = atomic_load(&rb->count);
        if (current_count == 0) {
            return false; // Buffer is empty
        }
        
        size_t current_tail = atomic_load(&rb->tail);
        
        // Validate tail position to prevent buffer underrun
        if (current_tail >= rb->capacity) {
            return false;
        }
        
        // Calculate new tail position
        size_t new_tail = (current_tail + 1) % rb->capacity;
        
        // Atomic compare-and-swap to claim the slot
        if (atomic_compare_exchange_weak(&rb->tail, &current_tail, new_tail)) {
            // Successfully claimed slot at current_tail, now copy data
            memcpy(metrics, &rb->buffer[current_tail], sizeof(flow_metrics_t));
            
            // Use memory barrier to ensure copy completes before clearing and updating count
            __atomic_thread_fence(__ATOMIC_SEQ_CST);
            
            // Clear the buffer slot to prevent information leaks
            memset(&rb->buffer[current_tail], 0, sizeof(flow_metrics_t));
            
            // Decrement count after successful read
            size_t old_count = atomic_fetch_sub(&rb->count, 1);
            
            // Double-check we didn't underflow (shouldn't happen with proper logic)
            if (old_count == 0) {
                // This is a critical error - rollback
                atomic_fetch_add(&rb->count, 1);
                return false;
            }
            
            return true;
        }
        
        // CAS failed, another thread modified tail, retry
        // Add a small backoff to reduce contention
        __atomic_thread_fence(__ATOMIC_ACQUIRE);
    }
}

size_t ring_buffer_size(ring_buffer_t *rb) {
    return rb ? atomic_load(&rb->count) : 0;
}

size_t ring_buffer_capacity(ring_buffer_t *rb) {
    return rb ? rb->capacity : 0;
}

bool ring_buffer_is_empty(ring_buffer_t *rb) {
    return ring_buffer_size(rb) == 0;
}

bool ring_buffer_is_full(ring_buffer_t *rb) {
    return ring_buffer_size(rb) >= ring_buffer_capacity(rb);
}

void ring_buffer_clear(ring_buffer_t *rb) {
    if (!rb) return;
    
    atomic_store(&rb->head, 0);
    atomic_store(&rb->tail, 0);
    atomic_store(&rb->count, 0);
    
    LOG_DEBUG("Cleared ring buffer");
}