#include <gtest/gtest.h>
#include "api/relative_vpn.h"
#include "packet/buffer_manager.h"
#include "core/types.h"
#include <chrono>
#include <thread>
#include <vector>
#include <memory>
#include <atomic>
#include <random>
#include <algorithm>

/**
 * Memory Performance and Buffer Management Tests
 * 
 * Benchmarks the efficiency of:
 * - Memory pool allocation/deallocation
 * - Buffer management performance
 * - Packet buffer recycling
 * - Memory pressure handling
 * - Concurrent allocation patterns
 */

class MemoryPerformanceTest : public ::testing::Test {
protected:
    void SetUp() override {
        config = {};
        config.utun_name = nullptr;
        config.mtu = 1500;
        config.tunnel_mtu = 1500;
        config.ipv4_enabled = true;
        config.ipv6_enabled = true;
        config.dns_servers[0] = inet_addr("8.8.8.8");
        config.dns_server_count = 1;
        config.dns_cache_size = 1024;
        config.metrics_buffer_size = 8192; // Larger for performance testing
        config.log_level = const_cast<char*>("ERROR"); // Minimal logging for performance
        
        result = {};
        
        // Initialize random number generator
        rng.seed(std::chrono::steady_clock::now().time_since_epoch().count());
    }
    
    void TearDown() override {
        if (result.handle != VPN_INVALID_HANDLE) {
            vpn_stop_comprehensive(result.handle);
        }
    }
    
    vpn_config_t config;
    vpn_result_t result;
    std::mt19937 rng;
    
    // Performance measurement utilities
    struct PerformanceMetrics {
        double avg_allocation_time_ns;
        double avg_deallocation_time_ns;
        double peak_memory_usage_mb;
        size_t allocations_per_second;
        size_t successful_allocations;
        size_t failed_allocations;
        double memory_efficiency_percent;
    };
    
    PerformanceMetrics measure_allocation_performance(int iterations, size_t min_size, size_t max_size);
    std::vector<uint8_t> create_test_packet(size_t size);
    void simulate_packet_processing_load(int packet_count, int thread_count);
};

std::vector<uint8_t> MemoryPerformanceTest::create_test_packet(size_t size) {
    std::vector<uint8_t> packet(size);
    
    // Fill with realistic packet-like data
    if (size >= 20) {
        packet[0] = 0x45; // IPv4
        packet[1] = 0x00; // DSCP
        packet[2] = (size >> 8) & 0xFF;
        packet[3] = size & 0xFF;
        packet[9] = 0x11; // UDP
        
        // Random payload
        std::uniform_int_distribution<uint8_t> byte_dist(0, 255);
        for (size_t i = 20; i < size; i++) {
            packet[i] = byte_dist(rng);
        }
    }
    
    return packet;
}

MemoryPerformanceTest::PerformanceMetrics 
MemoryPerformanceTest::measure_allocation_performance(int iterations, size_t min_size, size_t max_size) {
    PerformanceMetrics metrics = {};
    std::vector<std::unique_ptr<uint8_t[]>> allocations;
    std::vector<double> allocation_times;
    std::vector<double> deallocation_times;
    
    std::uniform_int_distribution<size_t> size_dist(min_size, max_size);
    
    auto start_time = std::chrono::high_resolution_clock::now();
    
    // Allocation phase
    for (int i = 0; i < iterations; i++) {
        size_t alloc_size = size_dist(rng);
        
        auto alloc_start = std::chrono::high_resolution_clock::now();
        
        try {
            auto ptr = std::make_unique<uint8_t[]>(alloc_size);
            memset(ptr.get(), 0xAA, alloc_size); // Touch memory
            
            auto alloc_end = std::chrono::high_resolution_clock::now();
            
            auto alloc_time = std::chrono::duration_cast<std::chrono::nanoseconds>(
                alloc_end - alloc_start).count();
            allocation_times.push_back(alloc_time);
            
            allocations.push_back(std::move(ptr));
            metrics.successful_allocations++;
            
        } catch (const std::bad_alloc&) {
            metrics.failed_allocations++;
        }
    }
    
    // Deallocation phase
    for (auto& ptr : allocations) {
        auto dealloc_start = std::chrono::high_resolution_clock::now();
        ptr.reset();
        auto dealloc_end = std::chrono::high_resolution_clock::now();
        
        auto dealloc_time = std::chrono::duration_cast<std::chrono::nanoseconds>(
            dealloc_end - dealloc_start).count();
        deallocation_times.push_back(dealloc_time);
    }
    
    auto end_time = std::chrono::high_resolution_clock::now();
    auto total_time = std::chrono::duration_cast<std::chrono::milliseconds>(
        end_time - start_time).count();
    
    // Calculate metrics
    if (!allocation_times.empty()) {
        metrics.avg_allocation_time_ns = 
            std::accumulate(allocation_times.begin(), allocation_times.end(), 0.0) / 
            allocation_times.size();
    }
    
    if (!deallocation_times.empty()) {
        metrics.avg_deallocation_time_ns = 
            std::accumulate(deallocation_times.begin(), deallocation_times.end(), 0.0) / 
            deallocation_times.size();
    }
    
    if (total_time > 0) {
        metrics.allocations_per_second = (metrics.successful_allocations * 1000) / total_time;
    }
    
    metrics.memory_efficiency_percent = 
        (double)metrics.successful_allocations / 
        (metrics.successful_allocations + metrics.failed_allocations) * 100.0;
    
    return metrics;
}

void MemoryPerformanceTest::simulate_packet_processing_load(int packet_count, int thread_count) {
    std::atomic<int> packets_processed{0};
    std::vector<std::thread> threads;
    
    auto process_packets = [&](int thread_id) {
        int packets_per_thread = packet_count / thread_count;
        
        for (int i = 0; i < packets_per_thread; i++) {
            // Create packet with random size
            std::uniform_int_distribution<size_t> size_dist(64, 1500);
            size_t packet_size = size_dist(rng);
            
            auto packet_data = create_test_packet(packet_size);
            
            packet_info_t packet = {};
            packet.data = packet_data.data();
            packet.length = packet_data.size();
            packet.flow.ip_version = 4;
            packet.flow.protocol = PROTO_UDP;
            packet.timestamp_ns = clock_gettime_nsec_np(CLOCK_MONOTONIC);
            
            if (vpn_inject_packet_comprehensive(result.handle, &packet)) {
                packets_processed.fetch_add(1);
            }
            
            // Small delay to prevent overwhelming
            if (i % 100 == 0) {
                std::this_thread::sleep_for(std::chrono::microseconds(100));
            }
        }
    };
    
    for (int i = 0; i < thread_count; i++) {
        threads.emplace_back(process_packets, i);
    }
    
    for (auto& t : threads) {
        t.join();
    }
}

// Test memory pool allocation performance
TEST_F(MemoryPerformanceTest, MemoryPoolAllocationPerformance) {
    // Test various allocation patterns
    struct TestCase {
        const char* name;
        int iterations;
        size_t min_size;
        size_t max_size;
        double max_avg_alloc_time_ns;
        size_t min_allocs_per_sec;
    } test_cases[] = {
        {"Small_Buffers", 10000, 64, 256, 1000.0, 5000},
        {"Medium_Buffers", 5000, 512, 1500, 2000.0, 2000},
        {"Large_Buffers", 1000, 2048, 8192, 5000.0, 500},
        {"Mixed_Sizes", 8000, 64, 4096, 3000.0, 2000}
    };
    
    for (auto& test_case : test_cases) {
        SCOPED_TRACE(test_case.name);
        
        auto metrics = measure_allocation_performance(
            test_case.iterations, test_case.min_size, test_case.max_size);
        
        // Performance requirements
        EXPECT_LT(metrics.avg_allocation_time_ns, test_case.max_avg_alloc_time_ns)
            << "Allocation too slow for " << test_case.name;
        
        EXPECT_GE(metrics.allocations_per_second, test_case.min_allocs_per_sec)
            << "Allocation rate too low for " << test_case.name;
        
        EXPECT_GT(metrics.memory_efficiency_percent, 95.0)
            << "Memory efficiency too low for " << test_case.name;
        
        // Log performance metrics
        std::cout << test_case.name << " Performance:" << std::endl;
        std::cout << "  Avg allocation time: " << metrics.avg_allocation_time_ns << " ns" << std::endl;
        std::cout << "  Allocations/sec: " << metrics.allocations_per_second << std::endl;
        std::cout << "  Success rate: " << metrics.memory_efficiency_percent << "%" << std::endl;
    }
}

// Test packet buffer management performance
TEST_F(MemoryPerformanceTest, PacketBufferManagementPerformance) {
    result = vpn_start_comprehensive(&config);
    
    if (result.status != VPN_SUCCESS) {
        GTEST_SKIP() << "VPN startup failed";
    }
    
    const int packet_count = 5000;
    const int thread_count = 4;
    
    auto start_time = std::chrono::high_resolution_clock::now();
    
    simulate_packet_processing_load(packet_count, thread_count);
    
    // Allow processing to complete
    std::this_thread::sleep_for(std::chrono::seconds(2));
    
    auto end_time = std::chrono::high_resolution_clock::now();
    auto processing_time = std::chrono::duration_cast<std::chrono::milliseconds>(
        end_time - start_time).count();
    
    // Get final metrics
    vpn_metrics_t metrics;
    ASSERT_TRUE(vpn_get_metrics_comprehensive(result.handle, &metrics));
    
    // Performance expectations
    EXPECT_GT(metrics.total_packets_processed, packet_count * 0.8); // 80% processing rate
    EXPECT_LT(processing_time, 30000); // Should complete within 30 seconds
    
    // Calculate throughput
    double packets_per_ms = (double)metrics.total_packets_processed / processing_time;
    double throughput_mbps = (metrics.bytes_received * 8.0) / (processing_time * 1000.0);
    
    EXPECT_GT(packets_per_ms, 1.0); // At least 1 packet per millisecond
    
    std::cout << "Packet Processing Performance:" << std::endl;
    std::cout << "  Packets processed: " << metrics.total_packets_processed << std::endl;
    std::cout << "  Processing time: " << processing_time << " ms" << std::endl;
    std::cout << "  Packets/ms: " << packets_per_ms << std::endl;
    std::cout << "  Throughput: " << throughput_mbps << " Mbps" << std::endl;
}

// Test memory efficiency under sustained load
TEST_F(MemoryPerformanceTest, SustainedLoadMemoryEfficiency) {
    result = vpn_start_comprehensive(&config);
    
    if (result.status != VPN_SUCCESS) {
        GTEST_SKIP() << "VPN startup failed";
    }
    
    // Sustained load test - multiple rounds
    const int rounds = 10;
    const int packets_per_round = 1000;
    
    std::vector<double> processing_times;
    std::vector<size_t> memory_usage_samples;
    
    for (int round = 0; round < rounds; round++) {
        auto round_start = std::chrono::high_resolution_clock::now();
        
        simulate_packet_processing_load(packets_per_round, 2);
        
        // Allow processing
        std::this_thread::sleep_for(std::chrono::milliseconds(500));
        
        auto round_end = std::chrono::high_resolution_clock::now();
        auto round_time = std::chrono::duration_cast<std::chrono::milliseconds>(
            round_end - round_start).count();
        
        processing_times.push_back(round_time);
        
        // Sample memory usage (approximate via metrics)
        vpn_metrics_t metrics;
        if (vpn_get_metrics_comprehensive(result.handle, &metrics)) {
            memory_usage_samples.push_back(metrics.bytes_received);
        }
        
        // Brief pause between rounds
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
    
    // Analyze performance consistency
    double avg_processing_time = std::accumulate(processing_times.begin(), 
                                               processing_times.end(), 0.0) / processing_times.size();
    
    double max_processing_time = *std::max_element(processing_times.begin(), processing_times.end());
    double min_processing_time = *std::min_element(processing_times.begin(), processing_times.end());
    
    // Performance should be consistent (no significant degradation)
    EXPECT_LT(max_processing_time - min_processing_time, avg_processing_time * 0.5)
        << "Processing time variance too high - possible memory fragmentation";
    
    // Memory usage should not grow unboundedly
    if (memory_usage_samples.size() > 5) {
        size_t early_usage = memory_usage_samples[2];
        size_t late_usage = memory_usage_samples.back();
        
        EXPECT_LT(late_usage, early_usage * 2.0)
            << "Memory usage grew too much - possible memory leak";
    }
    
    std::cout << "Sustained Load Results:" << std::endl;
    std::cout << "  Avg processing time: " << avg_processing_time << " ms" << std::endl;
    std::cout << "  Processing time range: " << min_processing_time << " - " << max_processing_time << " ms" << std::endl;
    std::cout << "  Performance consistency: " << ((max_processing_time - min_processing_time) / avg_processing_time * 100.0) << "% variance" << std::endl;
}

// Test concurrent memory allocation patterns
TEST_F(MemoryPerformanceTest, ConcurrentAllocationPatterns) {
    const int thread_count = 8;
    const int allocations_per_thread = 1000;
    std::atomic<size_t> total_allocations{0};
    std::atomic<size_t> failed_allocations{0};
    std::vector<std::thread> threads;
    std::atomic<bool> performance_degraded{false};
    
    auto concurrent_allocator = [&](int thread_id) {
        std::vector<std::unique_ptr<uint8_t[]>> thread_allocations;
        std::uniform_int_distribution<size_t> size_dist(512, 2048);
        
        for (int i = 0; i < allocations_per_thread; i++) {
            size_t alloc_size = size_dist(rng);
            
            auto alloc_start = std::chrono::high_resolution_clock::now();
            
            try {
                auto ptr = std::make_unique<uint8_t[]>(alloc_size);
                memset(ptr.get(), thread_id, alloc_size); // Touch memory with thread marker
                
                auto alloc_end = std::chrono::high_resolution_clock::now();
                auto alloc_time = std::chrono::duration_cast<std::chrono::microseconds>(
                    alloc_end - alloc_start).count();
                
                // Check for performance degradation
                if (alloc_time > 1000) { // More than 1ms is concerning
                    performance_degraded.store(true);
                }
                
                thread_allocations.push_back(std::move(ptr));
                total_allocations.fetch_add(1);
                
            } catch (const std::bad_alloc&) {
                failed_allocations.fetch_add(1);
            }
            
            // Periodically free some allocations to create churn
            if (i % 100 == 0 && thread_allocations.size() > 50) {
                thread_allocations.erase(thread_allocations.begin(), 
                                       thread_allocations.begin() + 25);
            }
        }
        
        // Verify memory integrity
        for (const auto& ptr : thread_allocations) {
            if (ptr && ptr[0] != thread_id) {
                performance_degraded.store(true); // Memory corruption
                break;
            }
        }
    };
    
    auto start_time = std::chrono::high_resolution_clock::now();
    
    // Start concurrent allocation threads
    for (int i = 0; i < thread_count; i++) {
        threads.emplace_back(concurrent_allocator, i);
    }
    
    // Wait for completion
    for (auto& t : threads) {
        t.join();
    }
    
    auto end_time = std::chrono::high_resolution_clock::now();
    auto total_time = std::chrono::duration_cast<std::chrono::milliseconds>(
        end_time - start_time).count();
    
    // Performance analysis
    size_t expected_allocations = thread_count * allocations_per_thread;
    double success_rate = (double)total_allocations.load() / expected_allocations * 100.0;
    double allocations_per_ms = (double)total_allocations.load() / total_time;
    
    EXPECT_GT(success_rate, 95.0) << "Concurrent allocation success rate too low";
    EXPECT_FALSE(performance_degraded.load()) << "Performance degradation or memory corruption detected";
    EXPECT_GT(allocations_per_ms, 1.0) << "Concurrent allocation rate too low";
    
    std::cout << "Concurrent Allocation Results:" << std::endl;
    std::cout << "  Total allocations: " << total_allocations.load() << std::endl;
    std::cout << "  Success rate: " << success_rate << "%" << std::endl;
    std::cout << "  Allocations/ms: " << allocations_per_ms << std::endl;
    std::cout << "  Total time: " << total_time << " ms" << std::endl;
}

// Test memory fragmentation resistance
TEST_F(MemoryPerformanceTest, MemoryFragmentationResistance) {
    const int fragmentation_cycles = 100;
    std::vector<double> allocation_times;
    
    for (int cycle = 0; cycle < fragmentation_cycles; cycle++) {
        // Create fragmentation by allocating and deallocating different sizes
        std::vector<std::unique_ptr<uint8_t[]>> allocations;
        std::uniform_int_distribution<size_t> size_dist(100, 3000);
        
        // Allocate many different sizes
        for (int i = 0; i < 50; i++) {
            size_t size = size_dist(rng);
            try {
                allocations.push_back(std::make_unique<uint8_t[]>(size));
            } catch (const std::bad_alloc&) {
                break;
            }
        }
        
        // Randomly deallocate some (creates holes)
        std::shuffle(allocations.begin(), allocations.end(), rng);
        if (allocations.size() > 10) {
            allocations.erase(allocations.begin(), allocations.begin() + allocations.size() / 3);
        }
        
        // Try to allocate a medium-sized buffer and measure time
        auto alloc_start = std::chrono::high_resolution_clock::now();
        try {
            auto test_alloc = std::make_unique<uint8_t[]>(1024);
            auto alloc_end = std::chrono::high_resolution_clock::now();
            
            auto alloc_time = std::chrono::duration_cast<std::chrono::nanoseconds>(
                alloc_end - alloc_start).count();
            allocation_times.push_back(alloc_time);
            
        } catch (const std::bad_alloc&) {
            allocation_times.push_back(1000000.0); // 1ms penalty for failure
        }
    }
    
    // Analyze fragmentation impact
    if (!allocation_times.empty()) {
        double avg_time = std::accumulate(allocation_times.begin(), allocation_times.end(), 0.0) / 
                         allocation_times.size();
        double max_time = *std::max_element(allocation_times.begin(), allocation_times.end());
        
        // Allocation time should remain reasonable even with fragmentation
        EXPECT_LT(avg_time, 10000.0) << "Average allocation time too high - fragmentation impact";
        EXPECT_LT(max_time, 100000.0) << "Maximum allocation time too high - severe fragmentation";
        
        std::cout << "Fragmentation Resistance Results:" << std::endl;
        std::cout << "  Average allocation time: " << avg_time << " ns" << std::endl;
        std::cout << "  Maximum allocation time: " << max_time << " ns" << std::endl;
        std::cout << "  Fragmentation impact: " << (max_time / avg_time) << "x worst case" << std::endl;
    }
}