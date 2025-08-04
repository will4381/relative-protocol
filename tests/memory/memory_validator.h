#ifndef MEMORY_VALIDATOR_H
#define MEMORY_VALIDATOR_H

#include <cstddef>
#include <vector>
#include <chrono>

#ifdef __APPLE__
#include <malloc/malloc.h>
#include <mach/mach.h>
#endif

/**
 * Advanced memory validation for macOS that distinguishes between
 * actual memory leaks and heap retention behavior.
 */
class MemoryValidator {
public:
    struct MemorySnapshot {
        size_t rss_bytes;           // Resident set size (what mach_task_basic_info reports)
        size_t heap_allocated;      // Actual heap allocations (more accurate for leaks)
        size_t heap_free_blocks;    // Free blocks in heap
        std::chrono::time_point<std::chrono::high_resolution_clock> timestamp;
    };
    
    /**
     * Take comprehensive memory snapshot
     */
    static MemorySnapshot take_snapshot();
    
    /**
     * Compare snapshots to detect actual leaks vs heap retention
     * Returns true if actual leak detected (not just heap retention)
     */
    static bool has_memory_leak(const MemorySnapshot& before, 
                               const MemorySnapshot& after,
                               size_t leak_threshold_bytes = 1024);
    
    /**
     * Run leak detection across multiple allocation cycles
     * This is the most reliable way to detect leaks on macOS
     */
    static bool validate_no_leaks_across_cycles(
        std::function<void()> allocation_test,
        int num_cycles = 5,
        size_t max_growth_bytes = 50 * 1024
    );
    
    /**
     * Force memory compaction (best effort on macOS)
     */
    static void force_memory_cleanup();
    
    /**
     * Get more accurate heap statistics than RSS
     */
    static size_t get_heap_allocated_bytes();
    
private:
    static size_t get_rss_bytes();
};

// Convenience macros for tests
#define EXPECT_NO_MEMORY_LEAK(test_func) \
    EXPECT_TRUE(MemoryValidator::validate_no_leaks_across_cycles([&]() { test_func; }))

#define ASSERT_NO_MEMORY_LEAK(test_func) \
    ASSERT_TRUE(MemoryValidator::validate_no_leaks_across_cycles([&]() { test_func; }))

#endif // MEMORY_VALIDATOR_H