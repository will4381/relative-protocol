#include <gtest/gtest.h>
#include "api/relative_vpn.h"
#include "metrics/ring_buffer.h"
#include "dns/resolver.h"
#include "privacy/guards.h"
#include "tcp_udp/connection_manager.h"
#include <thread>
#include <chrono>
#include <vector>
#include <atomic>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>

#ifdef __APPLE__
#include <malloc/malloc.h>
#include <mach/mach.h>
#endif

class MemoryLeakTest : public ::testing::Test {
protected:
    void SetUp() override {
        initial_memory = get_memory_usage();
        
        memset(&config, 0, sizeof(config));
        config.utun_name = nullptr;
        config.mtu = 1500;
        config.tunnel_mtu = 1500;
        config.ipv4_enabled = true;
        config.ipv6_enabled = false;
        config.enable_dns_leak_protection = true;
        config.enable_kill_switch = true;
        
        config.dns_server_count = 1;
        config.dns_servers[0] = inet_addr("8.8.8.8");
        
        config.enable_kill_switch = true;
        config.enable_dns_leak_protection = true;
    }
    
    void TearDown() override {
        if (result.handle != VPN_INVALID_HANDLE) {
            vpn_stop_comprehensive(result.handle);
        }
        
        // Force garbage collection and memory cleanup
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
        
        size_t final_memory = get_memory_usage();
        
        // Allow some memory growth but flag excessive leaks
        size_t memory_diff = final_memory - initial_memory;
        if (memory_diff > max_allowed_leak) {
            std::cerr << "WARNING: Potential memory leak detected. "
                      << "Memory increased by " << memory_diff << " bytes" << std::endl;
        }
    }
    
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
        // Linux implementation would go here
        return 0;
#endif
    }
    
    vpn_config_t config;
    vpn_result_t result = {};
    size_t initial_memory = 0;
    static constexpr size_t max_allowed_leak = 1024 * 1024; // 1MB allowance
};

TEST_F(MemoryLeakTest, VPNStartStopCycles) {
    const int num_cycles = 50;
    
    std::vector<size_t> memory_samples;
    memory_samples.reserve(num_cycles);
    
    for (int cycle = 0; cycle < num_cycles; cycle++) {
        // Start VPN
        result = vpn_start_comprehensive(&config);
        ASSERT_EQ(result.status, VPN_SUCCESS);
        
        // Generate some traffic
        for (int i = 0; i < 10; i++) {
            uint8_t packet[] = {
                0x45, 0x00, 0x00, 0x1c, 0x00, 0x01, 0x40, 0x00,
                0x40, 0x11, 0x00, 0x00, 0x0a, 0x00, 0x00, 0x01,
                0x08, 0x08, 0x08, 0x08, 0x00, 0x35, 0x00, 0x35,
                0x00, 0x08, 0x00, 0x00
            };
            
            packet_info_t pkt = {};
            pkt.data = packet;
            pkt.length = sizeof(packet);
            pkt.flow.ip_version = 4;
            pkt.flow.protocol = PROTO_UDP;
            pkt.flow.src_ip.v4.addr = inet_addr("10.0.0.1");
            pkt.flow.dst_ip.v4.addr = inet_addr("8.8.8.8");
            pkt.flow.src_port = 12345;
            pkt.flow.dst_port = 53;
            pkt.timestamp_ns = clock_gettime_nsec_np(CLOCK_MONOTONIC);
            
            vpn_inject_packet_comprehensive(result.handle, &pkt);
        }
        
        // Stop VPN
        EXPECT_TRUE(vpn_stop_comprehensive(result.handle));
        result.handle = VPN_INVALID_HANDLE;
        
        // Force cleanup
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
        
        // Sample memory
        size_t current_memory = get_memory_usage();
        memory_samples.push_back(current_memory);
        
        if (cycle > 0 && cycle % 10 == 0) {
            std::cout << "Cycle " << cycle << ", Memory: " << current_memory 
                      << " bytes (diff: +" << (current_memory - initial_memory) << ")" << std::endl;
        }
    }
    
    // Analyze memory trend
    size_t max_memory = *std::max_element(memory_samples.begin(), memory_samples.end());
    size_t min_memory = *std::min_element(memory_samples.begin(), memory_samples.end());
    size_t final_memory = memory_samples.back();
    
    std::cout << "Memory analysis:" << std::endl;
    std::cout << "  Initial: " << initial_memory << " bytes" << std::endl;
    std::cout << "  Maximum: " << max_memory << " bytes (+" << (max_memory - initial_memory) << ")" << std::endl;
    std::cout << "  Minimum: " << min_memory << " bytes (+" << (min_memory - initial_memory) << ")" << std::endl;
    std::cout << "  Final:   " << final_memory << " bytes (+" << (final_memory - initial_memory) << ")" << std::endl;
    
    // Memory should not grow unboundedly
    EXPECT_LT(final_memory - initial_memory, max_allowed_leak);
    
    // Memory should stabilize (not continuously growing)
    if (memory_samples.size() >= 20) {
        size_t early_avg = 0, late_avg = 0;
        for (int i = 5; i < 15; i++) early_avg += memory_samples[i];
        for (int i = memory_samples.size() - 10; i < memory_samples.size(); i++) late_avg += memory_samples[i];
        early_avg /= 10;
        late_avg /= 10;
        
        std::cout << "  Early average: " << early_avg << " bytes" << std::endl;
        std::cout << "  Late average:  " << late_avg << " bytes" << std::endl;
        
        // Allow some growth but not excessive
        EXPECT_LT(late_avg - early_avg, max_allowed_leak / 2);
    }
}

TEST_F(MemoryLeakTest, RingBufferOperations) {
    const int buffer_size = 10000;
    const int num_operations = 100000;
    
    size_t memory_before = get_memory_usage();
    
    ring_buffer_t *buffer = ring_buffer_create(buffer_size);
    ASSERT_NE(buffer, nullptr);
    
    // Perform many write/read operations
    for (int i = 0; i < num_operations; i++) {
        flow_metrics_t metrics = {};
        metrics.start_time_ns = clock_gettime_nsec_np(CLOCK_MONOTONIC);
        metrics.last_activity_ns = metrics.start_time_ns;
        metrics.bytes_in = i * 1400;
        metrics.bytes_out = i * 1200;
        metrics.packets_in = i;
        metrics.packets_out = i;
        metrics.protocol = 6; // TCP
        metrics.ip_version = 4;
        
        ring_buffer_push(buffer, &metrics);
        
        if (i % 2 == 0) {
            flow_metrics_t read_metrics;
            ring_buffer_pop(buffer, &read_metrics);
        }
    }
    
    size_t memory_during = get_memory_usage();
    
    ring_buffer_destroy(buffer);
    
    // Force cleanup
    std::this_thread::sleep_for(std::chrono::milliseconds(50));
    
    size_t memory_after = get_memory_usage();
    
    std::cout << "Ring buffer memory test:" << std::endl;
    std::cout << "  Before: " << memory_before << " bytes" << std::endl;
    std::cout << "  During: " << memory_during << " bytes (+" << (memory_during - memory_before) << ")" << std::endl;
    std::cout << "  After:  " << memory_after << " bytes (+" << (memory_after - memory_before) << ")" << std::endl;
    
    // Memory should return close to original after cleanup
    EXPECT_LT(memory_after - memory_before, 100 * 1024); // Allow 100KB variance
}

TEST_F(MemoryLeakTest, ConnectionManagerLifecycles) {
    const int num_managers = 100;
    const int connections_per_manager = 20;
    
    size_t memory_before = get_memory_usage();
    
    std::vector<connection_manager_t*> managers;
    managers.reserve(num_managers);
    
    // Create many connection managers
    for (int i = 0; i < num_managers; i++) {
        connection_manager_t *manager = connection_manager_create();
        ASSERT_NE(manager, nullptr);
        managers.push_back(manager);
        
        // Create connections for each manager
        for (int j = 0; j < connections_per_manager; j++) {
            ip_addr_t addr = { .v4 = { .addr = htonl(0xC0A80100 + j) } };
            
            // Alternate between TCP and UDP
            if (j % 2 == 0) {
                // Create TCP connection (simplified - may not actually connect)
                tcp_connection_t *conn = tcp_connection_create(manager, &addr, 80, nullptr, nullptr);
                if (conn) {
                    tcp_connection_destroy(conn);
                }
            } else {
                // Create UDP session
                udp_session_t *session = udp_session_create(manager, 0, nullptr, nullptr);
                if (session) {
                    udp_session_destroy(session);
                }
            }
        }
    }
    
    size_t memory_during = get_memory_usage();
    
    // Destroy all managers
    for (auto manager : managers) {
        connection_manager_destroy(manager);
    }
    managers.clear();
    
    // Force cleanup
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    
    size_t memory_after = get_memory_usage();
    
    std::cout << "Connection manager memory test:" << std::endl;
    std::cout << "  Before: " << memory_before << " bytes" << std::endl;
    std::cout << "  During: " << memory_during << " bytes (+" << (memory_during - memory_before) << ")" << std::endl;
    std::cout << "  After:  " << memory_after << " bytes (+" << (memory_after - memory_before) << ")" << std::endl;
    
    // Memory should return close to original
    EXPECT_LT(memory_after - memory_before, 500 * 1024); // Allow 500KB variance
}

TEST_F(MemoryLeakTest, DNSResolverLeaks) {
    const int num_resolvers = 50;
    const int queries_per_resolver = 10;
    
    size_t memory_before = get_memory_usage();
    
    for (int i = 0; i < num_resolvers; i++) {
        ip_addr_t google_dns = { .v4 = { .addr = inet_addr("8.8.8.8") } };
        dns_resolver_t *resolver = dns_resolver_create(&google_dns, 53);
        ASSERT_NE(resolver, nullptr);
        
        // Create and destroy queries
        for (int j = 0; j < queries_per_resolver; j++) {
            std::string hostname = "test" + std::to_string(i) + std::to_string(j) + ".example.com";
            
            dns_query_t *query = dns_resolver_query_async(resolver, hostname.c_str(), DNS_TYPE_A, nullptr, nullptr);
            if (query) {
                // Brief processing time
                std::this_thread::sleep_for(std::chrono::milliseconds(1));
            }
        }
        
        dns_resolver_destroy(resolver);
    }
    
    // Force cleanup
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    
    size_t memory_after = get_memory_usage();
    
    std::cout << "DNS resolver memory test:" << std::endl;
    std::cout << "  Before: " << memory_before << " bytes" << std::endl;
    std::cout << "  After:  " << memory_after << " bytes (+" << (memory_after - memory_before) << ")" << std::endl;
    
    // DNS resolvers should not leak memory
    EXPECT_LT(memory_after - memory_before, 200 * 1024); // Allow 200KB variance
}

TEST_F(MemoryLeakTest, PrivacyGuardsMemory) {
    const int num_guards = 100;
    const int packets_per_guard = 50;
    
    size_t memory_before = get_memory_usage();
    
    for (int i = 0; i < num_guards; i++) {
        privacy_guards_t *guards = privacy_guards_create();
        ASSERT_NE(guards, nullptr);
        
        // Configure DNS servers
        ip_addr_t allowed_dns[3] = {
            { .v4 = { .addr = inet_addr("8.8.8.8") } },
            { .v4 = { .addr = inet_addr("1.1.1.1") } },
            { .v4 = { .addr = inet_addr("9.9.9.9") } }
        };
        privacy_guards_set_allowed_dns_servers(guards, allowed_dns, 3);
        
        // Process packets
        for (int j = 0; j < packets_per_guard; j++) {
            uint8_t dns_packet[] = {
                0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x04, 't', 'e', 's',
                't', 0x03, 'c', 'o', 'm', 0x00, 0x00, 0x01, 0x00, 0x01
            };
            
            flow_tuple_t flow = {};
            flow.ip_version = 4;
            flow.protocol = PROTO_UDP;
            flow.src_ip.v4.addr = inet_addr("10.0.0.1");
            flow.dst_ip.v4.addr = allowed_dns[j % 3].v4.addr;
            flow.src_port = 12345;
            flow.dst_port = 53;
            
            bool should_block = false;
            privacy_guards_inspect_packet(guards, dns_packet, sizeof(dns_packet), &flow, &should_block);
        }
        
        privacy_guards_destroy(guards);
    }
    
    // Force cleanup
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    
    size_t memory_after = get_memory_usage();
    
    std::cout << "Privacy guards memory test:" << std::endl;
    std::cout << "  Before: " << memory_before << " bytes" << std::endl;
    std::cout << "  After:  " << memory_after << " bytes (+" << (memory_after - memory_before) << ")" << std::endl;
    
    // Privacy guards should not leak memory
    EXPECT_LT(memory_after - memory_before, 300 * 1024); // Allow 300KB variance
}

TEST_F(MemoryLeakTest, ConcurrentAllocationStress) {
    const int num_threads = 8;
    const int allocations_per_thread = 1000;
    
    std::atomic<int> completed_threads{0};
    std::vector<std::thread> threads;
    
    size_t memory_before = get_memory_usage();
    
    auto allocation_worker = [&](int thread_id) {
        for (int i = 0; i < allocations_per_thread; i++) {
            // Create and destroy various components
            switch (i % 4) {
                case 0: {
                    ring_buffer_t *buffer = ring_buffer_create(1000);
                    if (buffer) {
                        flow_metrics_t metrics = {};
                        metrics.start_time_ns = clock_gettime_nsec_np(CLOCK_MONOTONIC);
                        metrics.last_activity_ns = metrics.start_time_ns;
                        metrics.ip_version = 4;
                        metrics.protocol = 6;
                        for (int j = 0; j < 10; j++) {
                            ring_buffer_push(buffer, &metrics);
                        }
                        ring_buffer_destroy(buffer);
                    }
                    break;
                }
                case 1: {
                    privacy_guards_t *guards = privacy_guards_create();
                    if (guards) {
                        privacy_guards_destroy(guards);
                    }
                    break;
                }
                case 2: {
                    connection_manager_t *manager = connection_manager_create();
                    if (manager) {
                        connection_manager_destroy(manager);
                    }
                    break;
                }
                case 3: {
                    ip_addr_t dns_addr = { .v4 = { .addr = inet_addr("8.8.8.8") } };
                    dns_resolver_t *resolver = dns_resolver_create(&dns_addr, 53);
                    if (resolver) {
                        dns_resolver_destroy(resolver);
                    }
                    break;
                }
            }
            
            // Brief pause to allow other threads
            if (i % 100 == 0) {
                std::this_thread::sleep_for(std::chrono::milliseconds(1));
            }
        }
        
        completed_threads.fetch_add(1);
    };
    
    // Start all threads
    for (int i = 0; i < num_threads; i++) {
        threads.emplace_back(allocation_worker, i);
    }
    
    // Wait for completion
    for (auto& t : threads) {
        t.join();
    }
    
    // Force cleanup
    std::this_thread::sleep_for(std::chrono::milliseconds(200));
    
    size_t memory_after = get_memory_usage();
    
    std::cout << "Concurrent allocation stress test:" << std::endl;
    std::cout << "  Completed threads: " << completed_threads.load() << "/" << num_threads << std::endl;
    std::cout << "  Before: " << memory_before << " bytes" << std::endl;
    std::cout << "  After:  " << memory_after << " bytes (+" << (memory_after - memory_before) << ")" << std::endl;
    
    EXPECT_EQ(completed_threads.load(), num_threads);
    EXPECT_LT(memory_after - memory_before, max_allowed_leak);
}

TEST_F(MemoryLeakTest, LongRunningLeakDetection) {
    result = vpn_start_comprehensive(&config);
    ASSERT_EQ(result.status, VPN_SUCCESS);
    
    const auto test_duration = std::chrono::seconds(30);
    const int sample_interval_ms = 1000;
    
    std::vector<size_t> memory_timeline;
    auto start_time = std::chrono::high_resolution_clock::now();
    
    // Generate continuous traffic
    std::atomic<bool> traffic_running{true};
    std::thread traffic_thread([&]() {
        int packet_id = 0;
        while (traffic_running.load()) {
            uint8_t packet[] = {
                0x45, 0x00, 0x00, 0x1c, 0x00, 0x01, 0x40, 0x00,
                0x40, 0x11, 0x00, 0x00, 0x0a, 0x00, 0x00, 0x01,
                0x08, 0x08, 0x08, 0x08, 0x00, 0x35, 0x00, 0x35,
                0x00, 0x08, 0x00, 0x00
            };
            
            packet_info_t pkt = {};
            pkt.data = packet;
            pkt.length = sizeof(packet);
            pkt.flow.ip_version = 4;
            pkt.flow.protocol = PROTO_UDP;
            pkt.flow.src_ip.v4.addr = htonl(0x0A000001 + (packet_id % 254));
            pkt.flow.dst_ip.v4.addr = inet_addr("8.8.8.8");
            pkt.flow.src_port = 1000 + (packet_id % 1000);
            pkt.flow.dst_port = 53;
            pkt.timestamp_ns = clock_gettime_nsec_np(CLOCK_MONOTONIC);
            
            vpn_inject_packet_comprehensive(result.handle, &pkt);
            packet_id++;
            
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
        }
    });
    
    // Monitor memory usage over time
    while (std::chrono::high_resolution_clock::now() - start_time < test_duration) {
        memory_timeline.push_back(get_memory_usage());
        std::this_thread::sleep_for(std::chrono::milliseconds(sample_interval_ms));
    }
    
    traffic_running.store(false);
    traffic_thread.join();
    
    // Analyze memory trend
    if (memory_timeline.size() >= 3) {
        size_t start_memory = memory_timeline[0];
        size_t end_memory = memory_timeline.back();
        size_t max_memory = *std::max_element(memory_timeline.begin(), memory_timeline.end());
        
        std::cout << "Long-running leak detection:" << std::endl;
        std::cout << "  Duration: " << test_duration.count() << " seconds" << std::endl;
        std::cout << "  Samples: " << memory_timeline.size() << std::endl;
        std::cout << "  Start memory: " << start_memory << " bytes" << std::endl;
        std::cout << "  End memory:   " << end_memory << " bytes (+" << (end_memory - start_memory) << ")" << std::endl;
        std::cout << "  Peak memory:  " << max_memory << " bytes (+" << (max_memory - start_memory) << ")" << std::endl;
        
        // Calculate memory growth rate
        double growth_rate = (double)(end_memory - start_memory) / test_duration.count();
        std::cout << "  Growth rate: " << growth_rate << " bytes/second" << std::endl;
        
        // Memory should not grow excessively over time
        EXPECT_LT(end_memory - start_memory, max_allowed_leak);
        EXPECT_LT(growth_rate, 10000.0); // Less than 10KB/sec growth
    }
    
    vpn_metrics_t final_metrics;
    EXPECT_TRUE(vpn_get_metrics_comprehensive(result.handle, &final_metrics));
    std::cout << "  Packets processed: " << final_metrics.total_packets_processed << std::endl;
}

// Entry point for running memory tests independently
int main(int argc, char **argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}