/**
 * iOS Buffer Manager Test
 * Verifies that packet buffer management actually works
 */

#include "packet/buffer_manager.h"
#include <stdio.h>
#include <assert.h>
#include <string.h>

void test_buffer_pool_creation() {
    printf("Testing buffer pool creation...\n");
    
    buffer_pool_t *pool = buffer_pool_create(1500, 10);
    assert(pool != NULL);
    assert(pool->buffer_size == 1500);
    assert(pool->total_buffers == 10);
    assert(pool->free_count == 10);
    
    buffer_pool_destroy(pool);
    printf("✅ Buffer pool creation works\n");
}

void test_buffer_acquire_release() {
    printf("Testing buffer acquire/release...\n");
    
    buffer_pool_t *pool = buffer_pool_create(1500, 5);
    assert(pool != NULL);
    
    // Acquire buffers
    packet_buffer_t *buf1 = buffer_pool_acquire(pool);
    assert(buf1 != NULL);
    assert(buf1->capacity == 1500);
    assert(pool->free_count == 4);
    
    packet_buffer_t *buf2 = buffer_pool_acquire(pool);
    assert(buf2 != NULL);
    assert(pool->free_count == 3);
    
    // Test data writing
    const char *test_data = "Hello, VPN!";
    memcpy(buf1->data, test_data, strlen(test_data));
    buf1->length = strlen(test_data);
    assert(buf1->length == strlen(test_data));
    
    // Release buffers
    buffer_pool_release(pool, buf1);
    assert(pool->free_count == 4);
    
    buffer_pool_release(pool, buf2);
    assert(pool->free_count == 5);
    
    buffer_pool_destroy(pool);
    printf("✅ Buffer acquire/release works\n");
}

void test_buffer_reference_counting() {
    printf("Testing reference counting...\n");
    
    packet_buffer_t *buffer = packet_buffer_create(1024);
    assert(buffer != NULL);
    assert(atomic_load(&buffer->ref_count) == 1);
    
    // Increase reference
    packet_buffer_retain(buffer);
    assert(atomic_load(&buffer->ref_count) == 2);
    
    packet_buffer_retain(buffer);
    assert(atomic_load(&buffer->ref_count) == 3);
    
    // Release references
    packet_buffer_release(buffer);
    assert(atomic_load(&buffer->ref_count) == 2);
    
    packet_buffer_release(buffer);
    assert(atomic_load(&buffer->ref_count) == 1);
    
    // Final release should free the buffer
    packet_buffer_release(buffer);
    // Buffer is now freed, don't access it
    
    printf("✅ Reference counting works\n");
}

void test_safe_packet_operations() {
    printf("Testing safe packet operations...\n");
    
    // Create a safe packet
    uint8_t test_data[] = {0x45, 0x00, 0x00, 0x28}; // IPv4 header start
    flow_tuple_t flow = {
        .src_ip = 0x0100000A, // 10.0.0.1 in network byte order
        .dst_ip = 0x08080808, // 8.8.8.8
        .src_port = 12345,
        .dst_port = 80,
        .protocol = 6, // TCP
        .ip_version = 4
    };
    
    safe_packet_t *packet = safe_packet_create_copy(test_data, sizeof(test_data), &flow);
    assert(packet != NULL);
    assert(packet->buffer != NULL);
    assert(packet->buffer->length == sizeof(test_data));
    assert(memcmp(packet->buffer->data, test_data, sizeof(test_data)) == 0);
    
    // Test packet replacement
    uint8_t new_data[] = {0x60, 0x00, 0x00, 0x00}; // IPv6 header start
    bool replaced = safe_packet_replace_data(packet, new_data, sizeof(new_data));
    assert(replaced == true);
    assert(packet->buffer->length == sizeof(new_data));
    assert(memcmp(packet->buffer->data, new_data, sizeof(new_data)) == 0);
    
    safe_packet_destroy(packet);
    printf("✅ Safe packet operations work\n");
}

void test_buffer_pool_exhaustion() {
    printf("Testing buffer pool exhaustion...\n");
    
    buffer_pool_t *pool = buffer_pool_create(1500, 3);
    assert(pool != NULL);
    
    // Acquire all buffers
    packet_buffer_t *buf1 = buffer_pool_acquire(pool);
    packet_buffer_t *buf2 = buffer_pool_acquire(pool);
    packet_buffer_t *buf3 = buffer_pool_acquire(pool);
    
    assert(buf1 != NULL);
    assert(buf2 != NULL);
    assert(buf3 != NULL);
    assert(pool->free_count == 0);
    
    // Try to acquire one more - should fail or allocate new
    packet_buffer_t *buf4 = buffer_pool_acquire(pool);
    if (buf4 != NULL) {
        printf("  Pool auto-expanded (good!)\n");
        buffer_pool_release(pool, buf4);
    } else {
        printf("  Pool exhausted as expected\n");
    }
    
    // Release all
    buffer_pool_release(pool, buf1);
    buffer_pool_release(pool, buf2);
    buffer_pool_release(pool, buf3);
    
    buffer_pool_destroy(pool);
    printf("✅ Buffer pool exhaustion handled correctly\n");
}

int main() {
    printf("\n=== iOS Buffer Manager Tests ===\n\n");
    
    test_buffer_pool_creation();
    test_buffer_acquire_release();
    test_buffer_reference_counting();
    test_safe_packet_operations();
    test_buffer_pool_exhaustion();
    
    printf("\n✅ All buffer manager tests passed!\n\n");
    return 0;
}