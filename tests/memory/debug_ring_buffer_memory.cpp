#include <iostream>
#include <vector>
#include <thread>
#include <chrono>
#include "metrics/ring_buffer.h"

#ifdef __APPLE__
#include <mach/mach.h>
#include <malloc/malloc.h>
#endif

size_t get_memory_usage() {
#ifdef __APPLE__
    struct mach_task_basic_info info;
    mach_msg_type_number_t infoCount = MACH_TASK_BASIC_INFO_COUNT;
    if (task_info(mach_task_self(), MACH_TASK_BASIC_INFO,
                  (task_info_t)&info, &infoCount) != KERN_SUCCESS) {
        return 0;
    }
    return info.resident_size;
#else
    return 0;
#endif
}

size_t get_heap_usage() {
#ifdef __APPLE__
    malloc_statistics_t stats;
    malloc_zone_statistics(nullptr, &stats);
    return stats.size_in_use;
#else
    return 0;
#endif
}

void print_memory_info(const std::string& label) {
    size_t rss = get_memory_usage();
    size_t heap = get_heap_usage();
    std::cout << label << ": RSS=" << rss << " bytes, Heap=" << heap << " bytes" << std::endl;
}

int main() {
    std::cout << "=== Ring Buffer Memory Debug Test ===" << std::endl;
    
    print_memory_info("Initial");
    
    const int buffer_size = 10000;
    const int num_operations = 100000;
    const int num_cycles = 3;
    
    std::vector<ring_buffer_t*> buffers;
    
    // Test 1: Create multiple buffers simultaneously (should show if destruction is working)
    std::cout << "\n--- Test 1: Create " << num_cycles << " buffers simultaneously ---" << std::endl;
    
    for (int i = 0; i < num_cycles; i++) {
        ring_buffer_t *buffer = ring_buffer_create(buffer_size);
        if (!buffer) {
            std::cout << "Failed to create buffer " << i << std::endl;
            continue;
        }
        buffers.push_back(buffer);
        print_memory_info("After creating buffer " + std::to_string(i+1));
    }
    
    // Destroy all at once
    for (auto* buffer : buffers) {
        ring_buffer_destroy(buffer);
    }
    buffers.clear();
    
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    print_memory_info("After destroying all buffers");
    
    // Test 2: Create and destroy in sequence (what the test was doing)
    std::cout << "\n--- Test 2: Create/destroy cycles ---" << std::endl;
    
    for (int cycle = 0; cycle < num_cycles; cycle++) {
        ring_buffer_t *buffer = ring_buffer_create(buffer_size);
        if (!buffer) {
            std::cout << "Failed to create buffer in cycle " << cycle << std::endl;
            continue;
        }
        
        // Perform operations
        for (int i = 0; i < num_operations; i++) {
            flow_metrics_t metrics = {};
            metrics.start_time_ns = 12345;
            metrics.last_activity_ns = 12345;
            metrics.bytes_in = i * 1400;
            metrics.bytes_out = i * 1200;
            metrics.packets_in = i;
            metrics.packets_out = i;
            metrics.protocol = 6;
            metrics.ip_version = 4;
            
            ring_buffer_push(buffer, &metrics);
            
            if (i % 2 == 0) {
                flow_metrics_t read_metrics;
                ring_buffer_pop(buffer, &read_metrics);
            }
        }
        
        print_memory_info("After operations in cycle " + std::to_string(cycle+1));
        
        ring_buffer_destroy(buffer);
        
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
        print_memory_info("After destroying buffer in cycle " + std::to_string(cycle+1));
    }
    
    // Test 3: Force memory cleanup
    std::cout << "\n--- Test 3: Memory cleanup attempts ---" << std::endl;
    
#ifdef __APPLE__
    // Try to force malloc to release memory
    malloc_zone_t* zone = malloc_default_zone();
    if (zone && zone->pressure_relief) {
        zone->pressure_relief(zone, 0);
        print_memory_info("After pressure_relief");
    }
#endif
    
    // Sleep and check if memory comes down
    for (int i = 1; i <= 5; i++) {
        std::this_thread::sleep_for(std::chrono::milliseconds(500));
        print_memory_info("After " + std::to_string(i * 500) + "ms wait");
    }
    
    return 0;
}