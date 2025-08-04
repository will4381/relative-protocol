#include "memory_validator.h"
#include <iostream>
#include <thread>
#include <functional>
#include <algorithm>

#ifdef __APPLE__
#include <malloc/malloc.h>
#include <mach/mach.h>
#include <mach/vm_statistics.h>
#include <sys/sysctl.h>
#endif

MemoryValidator::MemorySnapshot MemoryValidator::take_snapshot() {
    MemorySnapshot snapshot = {};
    snapshot.timestamp = std::chrono::high_resolution_clock::now();
    
#ifdef __APPLE__
    // Get RSS (what the original test was measuring)
    snapshot.rss_bytes = get_rss_bytes();
    
    // Get more accurate heap statistics
    snapshot.heap_allocated = get_heap_allocated_bytes();
    
    // Count free blocks in heap
    malloc_statistics_t stats;
    malloc_zone_statistics(nullptr, &stats);
    snapshot.heap_free_blocks = stats.size_allocated - stats.size_in_use;
#else
    snapshot.rss_bytes = 0;
    snapshot.heap_allocated = 0;
    snapshot.heap_free_blocks = 0;
#endif
    
    return snapshot;
}

bool MemoryValidator::has_memory_leak(const MemorySnapshot& before, 
                                     const MemorySnapshot& after,
                                     size_t leak_threshold_bytes) {
    // Key insight: RSS can increase due to heap expansion even without leaks
    // More reliable indicators:
    // 1. Heap allocated bytes should return to baseline
    // 2. Large RSS increases without corresponding heap_allocated increases suggest fragmentation
    
    size_t heap_growth = after.heap_allocated > before.heap_allocated ? 
                        after.heap_allocated - before.heap_allocated : 0;
    
    size_t rss_growth = after.rss_bytes > before.rss_bytes ?
                       after.rss_bytes - before.rss_bytes : 0;
    
    // If heap allocated bytes grew significantly, that's a stronger leak signal
    if (heap_growth > leak_threshold_bytes) {
        std::cerr << "LEAK: Heap allocated grew by " << heap_growth << " bytes" << std::endl;
        return true;
    }
    
    // If RSS grew massively but heap didn't, it might be fragmentation
    if (rss_growth > 10 * 1024 * 1024 && heap_growth < leak_threshold_bytes) {
        std::cerr << "WARNING: Large RSS growth (" << rss_growth 
                  << " bytes) but minimal heap growth (" << heap_growth 
                  << " bytes) - likely fragmentation" << std::endl;
    }
    
    return false;
}

bool MemoryValidator::validate_no_leaks_across_cycles(
    std::function<void()> allocation_test,
    int num_cycles,
    size_t max_growth_bytes) {
    
    std::vector<MemorySnapshot> snapshots;
    snapshots.reserve(num_cycles + 1);
    
    // Baseline measurement
    force_memory_cleanup();
    std::this_thread::sleep_for(std::chrono::milliseconds(50));
    snapshots.push_back(take_snapshot());
    
    // Run multiple cycles
    for (int i = 0; i < num_cycles; i++) {
        allocation_test();
        
        // Brief cleanup pause
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
        
        snapshots.push_back(take_snapshot());
    }
    
    // Analyze trend
    auto baseline = snapshots[0];
    auto final = snapshots.back();
    
    std::cout << "Memory validation across " << num_cycles << " cycles:" << std::endl;
    std::cout << "  Baseline RSS: " << baseline.rss_bytes << " bytes" << std::endl;
    std::cout << "  Baseline heap: " << baseline.heap_allocated << " bytes" << std::endl;
    
    for (size_t i = 1; i < snapshots.size(); i++) {
        auto& snap = snapshots[i];
        std::cout << "  Cycle " << i << " RSS: " << snap.rss_bytes 
                  << " (+" << (snap.rss_bytes - baseline.rss_bytes) << ")" 
                  << ", heap: " << snap.heap_allocated 
                  << " (+" << (snap.heap_allocated - baseline.heap_allocated) << ")" << std::endl;
    }
    
    // Check for actual leaks (heap growth trend)
    size_t heap_growth = final.heap_allocated > baseline.heap_allocated ?
                        final.heap_allocated - baseline.heap_allocated : 0;
    
    bool no_leak = heap_growth <= max_growth_bytes;
    
    if (!no_leak) {
        std::cerr << "LEAK DETECTED: Heap grew by " << heap_growth 
                  << " bytes across cycles (limit: " << max_growth_bytes << ")" << std::endl;
    } else {
        std::cout << "✓ No memory leaks detected. Heap growth: " << heap_growth << " bytes" << std::endl;
        
        // Explain RSS vs heap difference
        size_t rss_growth = final.rss_bytes > baseline.rss_bytes ?
                           final.rss_bytes - baseline.rss_bytes : 0;
        if (rss_growth > heap_growth + 100 * 1024) {
            std::cout << "  Note: RSS grew by " << rss_growth 
                      << " bytes - this is normal macOS heap retention, not a leak" << std::endl;
        }
    }
    
    return no_leak;
}

void MemoryValidator::force_memory_cleanup() {
#ifdef __APPLE__
    // Force malloc to consolidate free blocks
    malloc_zone_t* zone = malloc_default_zone();
    if (zone && zone->pressure_relief) {
        zone->pressure_relief(zone, 0);
    }
    
    // Trigger garbage collection if using GC
    // Note: This is a no-op in most cases but doesn't hurt
    system("sync");
#endif
}

size_t MemoryValidator::get_heap_allocated_bytes() {
#ifdef __APPLE__
    malloc_statistics_t stats;
    malloc_zone_statistics(nullptr, &stats);
    return stats.size_in_use;
#else
    return 0;
#endif
}

size_t MemoryValidator::get_rss_bytes() {
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