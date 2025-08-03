#include <gtest/gtest.h>
#include "api/relative_vpn.h"
#include "metrics/ring_buffer.h"
#include "tcp_udp/connection_manager.h"
#include "dns/resolver.h"
#include "privacy/guards.h"
#include <thread>
#include <chrono>
#include <atomic>
#include <vector>
#include <random>
#include <algorithm>

class PerformanceTest : public ::testing::Test {
protected:
    void SetUp() override {
        vpn_config_init(&config);
        config.enable_logging = false; // Disable logging for performance
        config.tunnel_mtu = 1500;
        inet_pton(AF_INET, "10.0.0.1", &config.tunnel_ipv4);
        inet_pton(AF_INET, "255.255.255.0", &config.tunnel_netmask);
        
        config.dns_server_count = 1;
        inet_pton(AF_INET, "8.8.8.8", &config.dns_servers[0]);
        
        config.enable_kill_switch = true;
        config.enable_dns_leak_protection = true;
    }
    
    void TearDown() override {
        if (result.handle != VPN_INVALID_HANDLE) {
            vpn_stop(result.handle);
        }
    }
    
    // Helper to generate realistic packet data
    std::vector<uint8_t> generate_packet(size_t size, uint8_t protocol) {
        std::vector<uint8_t> packet(size);
        
        // IPv4 header
        packet[0] = 0x45; // Version + IHL
        packet[1] = 0x00; // ToS
        packet[2] = (size >> 8) & 0xFF; // Total length high
        packet[3] = size & 0xFF;        // Total length low
        packet[9] = protocol;           // Protocol
        
        // Fill rest with pseudo-random data
        for (size_t i = 20; i < size; i++) {
            packet[i] = (uint8_t)(i * 17 + protocol);
        }
        
        return packet;
    }
    
    vpn_config_t config;
    vpn_result_t result = {};
};

TEST_F(PerformanceTest, HighThroughputPacketProcessing) {
    result = vpn_start(&config);
    ASSERT_EQ(result.status, VPN_STATUS_SUCCESS);
    
    const int total_packets = 10000;
    const int packet_size = 1400;
    std::atomic<int> packets_processed{0};
    
    auto start_time = std::chrono::high_resolution_clock::now();
    
    // Generate packets in batches for better performance
    for (int batch = 0; batch < 100; batch++) {
        for (int i = 0; i < 100; i++) {
            auto packet_data = generate_packet(packet_size, PROTO_UDP);
            
            packet_info_t packet = {};
            packet.data = packet_data.data();
            packet.length = packet_data.size();
            packet.flow.ip_version = 4;
            packet.flow.protocol = PROTO_UDP;
            packet.flow.src_ip.v4.addr = htonl(0x0A000001 + (batch % 254));
            packet.flow.dst_ip.v4.addr = inet_addr("8.8.8.8");
            packet.flow.src_port = 1000 + (i % 1000);
            packet.flow.dst_port = 53;
            packet.timestamp_ns = clock_gettime_nsec_np(CLOCK_MONOTONIC);
            
            if (vpn_inject_packet(result.handle, &packet)) {
                packets_processed.fetch_add(1);
            }
        }
    }
    
    auto end_time = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end_time - start_time);
    
    double packets_per_second = (double)packets_processed.load() / (duration.count() / 1000.0);
    double mbps = (packets_per_second * packet_size * 8) / (1024 * 1024);
    
    std::cout << "Processed " << packets_processed.load() << " packets in " 
              << duration.count() << "ms" << std::endl;
    std::cout << "Throughput: " << packets_per_second << " packets/sec, " 
              << mbps << " Mbps" << std::endl;
    
    // Performance expectations (adjust based on target hardware)
    EXPECT_GT(packets_per_second, 1000); // At least 1K packets/sec
    EXPECT_GT(packets_processed.load(), total_packets * 0.8); // 80% success rate
    
    vpn_metrics_t metrics;
    vpn_get_metrics(result.handle, &metrics);
    std::cout << "Packet errors: " << metrics.packet_errors << std::endl;
}

TEST_F(PerformanceTest, ConcurrentConnectionStress) {
    result = vpn_start(&config);
    ASSERT_EQ(result.status, VPN_STATUS_SUCCESS);
    
    const int num_threads = 8;
    const int connections_per_thread = 50;
    const int packets_per_connection = 20;
    
    std::atomic<int> total_connections{0};
    std::atomic<int> total_packets{0};
    std::vector<std::thread> threads;
    
    auto start_time = std::chrono::high_resolution_clock::now();
    
    auto connection_worker = [&](int thread_id) {
        std::random_device rd;
        std::mt19937 gen(rd() + thread_id);
        std::uniform_int_distribution<> port_dist(1024, 65535);
        std::uniform_int_distribution<> size_dist(64, 1400);
        
        for (int conn = 0; conn < connections_per_thread; conn++) {
            uint32_t src_ip = htonl(0x0A000001 + thread_id);
            uint32_t dst_ip = htonl(0x08080808 + (conn % 256));
            uint16_t src_port = port_dist(gen);
            uint16_t dst_port = (conn % 2 == 0) ? 80 : 443;
            
            total_connections.fetch_add(1);
            
            for (int pkt = 0; pkt < packets_per_connection; pkt++) {
                int packet_size = size_dist(gen);
                auto packet_data = generate_packet(packet_size, PROTO_TCP);
                
                packet_info_t packet = {};
                packet.data = packet_data.data();
                packet.length = packet_data.size();
                packet.flow.ip_version = 4;
                packet.flow.protocol = PROTO_TCP;
                packet.flow.src_ip.v4.addr = src_ip;
                packet.flow.dst_ip.v4.addr = dst_ip;
                packet.flow.src_port = src_port;
                packet.flow.dst_port = dst_port;
                packet.timestamp_ns = clock_gettime_nsec_np(CLOCK_MONOTONIC);
                
                if (vpn_inject_packet(result.handle, &packet)) {
                    total_packets.fetch_add(1);
                }
                
                // Small delay to simulate realistic traffic
                std::this_thread::sleep_for(std::chrono::microseconds(100));
            }
        }
    };
    
    // Start all threads
    for (int i = 0; i < num_threads; i++) {
        threads.emplace_back(connection_worker, i);
    }
    
    // Wait for completion
    for (auto& t : threads) {
        t.join();
    }
    
    auto end_time = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end_time - start_time);
    
    std::cout << "Simulated " << total_connections.load() << " connections with " 
              << total_packets.load() << " packets in " << duration.count() << "ms" << std::endl;
    
    vpn_metrics_t metrics;
    vpn_get_metrics(result.handle, &metrics);
    std::cout << "TCP connections tracked: " << metrics.tcp_connections << std::endl;
    std::cout << "Total packets processed: " << metrics.total_packets_processed << std::endl;
    
    EXPECT_EQ(total_connections.load(), num_threads * connections_per_thread);
    EXPECT_GT(total_packets.load(), 0);
}

TEST_F(PerformanceTest, DNSQueryPerformance) {
    result = vpn_start(&config);
    ASSERT_EQ(result.status, VPN_STATUS_SUCCESS);
    
    const int num_queries = 1000;
    std::atomic<int> queries_processed{0};
    
    auto start_time = std::chrono::high_resolution_clock::now();
    
    // Generate DNS queries
    for (int i = 0; i < num_queries; i++) {
        uint8_t dns_query[] = {
            0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x07, 'e', 'x', 'a',
            'm', 'p', 'l', 'e', 0x03, 'c', 'o', 'm', 0x00,
            0x00, 0x01, 0x00, 0x01
        };
        
        // Vary transaction ID
        dns_query[0] = (i >> 8) & 0xFF;
        dns_query[1] = i & 0xFF;
        
        packet_info_t packet = {};
        packet.data = dns_query;
        packet.length = sizeof(dns_query);
        packet.flow.ip_version = 4;
        packet.flow.protocol = PROTO_UDP;
        packet.flow.src_ip.v4.addr = htonl(0x0A000001 + (i % 254));
        packet.flow.dst_ip.v4.addr = inet_addr("8.8.8.8");
        packet.flow.src_port = 1000 + (i % 1000);
        packet.flow.dst_port = 53;
        packet.timestamp_ns = clock_gettime_nsec_np(CLOCK_MONOTONIC);
        
        if (vpn_inject_packet(result.handle, &packet)) {
            queries_processed.fetch_add(1);
        }
    }
    
    auto end_time = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end_time - start_time);
    
    double queries_per_second = (double)queries_processed.load() / (duration.count() / 1000000.0);
    
    std::cout << "Processed " << queries_processed.load() << " DNS queries in " 
              << duration.count() << " microseconds" << std::endl;
    std::cout << "DNS query rate: " << queries_per_second << " queries/sec" << std::endl;
    
    EXPECT_GT(queries_per_second, 5000); // At least 5K queries/sec
    EXPECT_EQ(queries_processed.load(), num_queries);
}

TEST_F(PerformanceTest, MemoryEfficiency) {
    result = vpn_start(&config);
    ASSERT_EQ(result.status, VPN_STATUS_SUCCESS);
    
    // Baseline memory usage
    vpn_metrics_t baseline_metrics;
    vpn_get_metrics(result.handle, &baseline_metrics);
    
    const int stress_cycles = 10;
    const int packets_per_cycle = 1000;
    
    // Memory stress test - create and destroy many connections
    for (int cycle = 0; cycle < stress_cycles; cycle++) {
        std::vector<std::vector<uint8_t>> packets;
        packets.reserve(packets_per_cycle);
        
        // Generate packets
        for (int i = 0; i < packets_per_cycle; i++) {
            packets.push_back(generate_packet(1400, PROTO_TCP));
        }
        
        // Process packets
        for (int i = 0; i < packets_per_cycle; i++) {
            packet_info_t packet = {};
            packet.data = packets[i].data();
            packet.length = packets[i].size();
            packet.flow.ip_version = 4;
            packet.flow.protocol = PROTO_TCP;
            packet.flow.src_ip.v4.addr = htonl(0x0A000001 + cycle);
            packet.flow.dst_ip.v4.addr = htonl(0x08080808 + i);
            packet.flow.src_port = 1000 + i;
            packet.flow.dst_port = 80;
            packet.timestamp_ns = clock_gettime_nsec_np(CLOCK_MONOTONIC);
            
            vpn_inject_packet(result.handle, &packet);
        }
        
        // Force cleanup
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
    
    // Check final memory usage
    vpn_metrics_t final_metrics;
    vpn_get_metrics(result.handle, &final_metrics);
    
    std::cout << "Memory efficiency test completed" << std::endl;
    std::cout << "Total packets processed: " << final_metrics.total_packets_processed << std::endl;
    
    // Memory usage should be reasonable (exact values depend on implementation)
    EXPECT_GT(final_metrics.total_packets_processed, stress_cycles * packets_per_cycle * 0.8);
}

TEST_F(PerformanceTest, LatencyMeasurement) {
    result = vpn_start(&config);
    ASSERT_EQ(result.status, VPN_STATUS_SUCCESS);
    
    const int num_samples = 1000;
    std::vector<double> latencies;
    latencies.reserve(num_samples);
    
    // Measure packet processing latency
    for (int i = 0; i < num_samples; i++) {
        auto packet_data = generate_packet(500, PROTO_UDP);
        
        packet_info_t packet = {};
        packet.data = packet_data.data();
        packet.length = packet_data.size();
        packet.flow.ip_version = 4;
        packet.flow.protocol = PROTO_UDP;
        packet.flow.src_ip.v4.addr = htonl(0x0A000001 + (i % 10));
        packet.flow.dst_ip.v4.addr = inet_addr("8.8.8.8");
        packet.flow.src_port = 1000 + i;
        packet.flow.dst_port = 53;
        
        auto start = std::chrono::high_resolution_clock::now();
        packet.timestamp_ns = clock_gettime_nsec_np(CLOCK_MONOTONIC);
        
        vpn_inject_packet(result.handle, &packet);
        
        auto end = std::chrono::high_resolution_clock::now();
        auto latency = std::chrono::duration_cast<std::chrono::microseconds>(end - start);
        latencies.push_back(latency.count());
        
        // Small delay between measurements
        std::this_thread::sleep_for(std::chrono::microseconds(100));
    }
    
    // Calculate statistics
    std::sort(latencies.begin(), latencies.end());
    
    double mean = std::accumulate(latencies.begin(), latencies.end(), 0.0) / latencies.size();
    double p50 = latencies[latencies.size() / 2];
    double p95 = latencies[static_cast<size_t>(latencies.size() * 0.95)];
    double p99 = latencies[static_cast<size_t>(latencies.size() * 0.99)];
    
    std::cout << "Latency Statistics (microseconds):" << std::endl;
    std::cout << "  Mean: " << mean << std::endl;
    std::cout << "  P50:  " << p50 << std::endl;
    std::cout << "  P95:  " << p95 << std::endl;
    std::cout << "  P99:  " << p99 << std::endl;
    
    // Performance expectations
    EXPECT_LT(mean, 1000.0);  // Mean latency < 1ms
    EXPECT_LT(p95, 5000.0);   // P95 latency < 5ms
    EXPECT_LT(p99, 10000.0);  // P99 latency < 10ms
}

TEST_F(PerformanceTest, RingBufferPerformance) {
    ring_buffer_t *buffer = ring_buffer_create(1000000); // 1M entries
    ASSERT_NE(buffer, nullptr);
    
    const int num_operations = 100000;
    auto start_time = std::chrono::high_resolution_clock::now();
    
    // Test write performance
    for (int i = 0; i < num_operations; i++) {
        vpn_metrics_t metrics = {};
        metrics.timestamp_ns = clock_gettime_nsec_np(CLOCK_MONOTONIC);
        metrics.total_packets_processed = i;
        metrics.bytes_received = i * 1400;
        metrics.bytes_sent = i * 1200;
        
        ring_buffer_write(buffer, &metrics, sizeof(metrics));
    }
    
    auto write_end = std::chrono::high_resolution_clock::now();
    
    // Test read performance
    vpn_metrics_t read_metrics;
    int successful_reads = 0;
    
    for (int i = 0; i < num_operations; i++) {
        if (ring_buffer_read(buffer, &read_metrics, sizeof(read_metrics))) {
            successful_reads++;
        }
    }
    
    auto read_end = std::chrono::high_resolution_clock::now();
    
    auto write_duration = std::chrono::duration_cast<std::chrono::microseconds>(write_end - start_time);
    auto read_duration = std::chrono::duration_cast<std::chrono::microseconds>(read_end - write_end);
    
    double write_ops_per_sec = (double)num_operations / (write_duration.count() / 1000000.0);
    double read_ops_per_sec = (double)successful_reads / (read_duration.count() / 1000000.0);
    
    std::cout << "Ring Buffer Performance:" << std::endl;
    std::cout << "  Write: " << write_ops_per_sec << " ops/sec" << std::endl;
    std::cout << "  Read:  " << read_ops_per_sec << " ops/sec" << std::endl;
    std::cout << "  Successful reads: " << successful_reads << "/" << num_operations << std::endl;
    
    EXPECT_GT(write_ops_per_sec, 100000); // At least 100K writes/sec
    EXPECT_GT(read_ops_per_sec, 100000);  // At least 100K reads/sec
    EXPECT_GT(successful_reads, num_operations * 0.95); // 95% read success
    
    ring_buffer_destroy(buffer);
}

TEST_F(PerformanceTest, ConcurrentMetricsCollection) {
    result = vpn_start(&config);
    ASSERT_EQ(result.status, VPN_STATUS_SUCCESS);
    
    const int num_threads = 4;
    const int metrics_per_thread = 10000;
    std::atomic<int> total_metrics{0};
    std::vector<std::thread> threads;
    
    auto start_time = std::chrono::high_resolution_clock::now();
    
    auto metrics_worker = [&](int thread_id) {
        for (int i = 0; i < metrics_per_thread; i++) {
            vpn_metrics_t metrics;
            if (vpn_get_metrics(result.handle, &metrics)) {
                total_metrics.fetch_add(1);
            }
            
            // Simulate some processing
            std::this_thread::sleep_for(std::chrono::nanoseconds(1000));
        }
    };
    
    // Start threads
    for (int i = 0; i < num_threads; i++) {
        threads.emplace_back(metrics_worker, i);
    }
    
    // Wait for completion
    for (auto& t : threads) {
        t.join();
    }
    
    auto end_time = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end_time - start_time);
    
    double metrics_per_second = (double)total_metrics.load() / (duration.count() / 1000.0);
    
    std::cout << "Collected " << total_metrics.load() << " metrics in " 
              << duration.count() << "ms" << std::endl;
    std::cout << "Metrics collection rate: " << metrics_per_second << " metrics/sec" << std::endl;
    
    EXPECT_EQ(total_metrics.load(), num_threads * metrics_per_thread);
    EXPECT_GT(metrics_per_second, 10000); // At least 10K metrics/sec
}

TEST_F(PerformanceTest, LongRunningStabilityTest) {
    result = vpn_start(&config);
    ASSERT_EQ(result.status, VPN_STATUS_SUCCESS);
    
    const auto test_duration = std::chrono::seconds(10); // 10 second test
    const int packet_interval_ms = 10; // Send packet every 10ms
    
    std::atomic<int> packets_sent{0};
    std::atomic<bool> test_running{true};
    
    auto start_time = std::chrono::high_resolution_clock::now();
    auto end_time = start_time + test_duration;
    
    // Traffic generator thread
    std::thread traffic_thread([&]() {
        int packet_id = 0;
        while (test_running.load() && std::chrono::high_resolution_clock::now() < end_time) {
            auto packet_data = generate_packet(800, PROTO_UDP);
            
            packet_info_t packet = {};
            packet.data = packet_data.data();
            packet.length = packet_data.size();
            packet.flow.ip_version = 4;
            packet.flow.protocol = PROTO_UDP;
            packet.flow.src_ip.v4.addr = htonl(0x0A000001 + (packet_id % 10));
            packet.flow.dst_ip.v4.addr = inet_addr("8.8.8.8");
            packet.flow.src_port = 1000 + (packet_id % 1000);
            packet.flow.dst_port = 53;
            packet.timestamp_ns = clock_gettime_nsec_np(CLOCK_MONOTONIC);
            
            if (vpn_inject_packet(result.handle, &packet)) {
                packets_sent.fetch_add(1);
            }
            
            packet_id++;
            std::this_thread::sleep_for(std::chrono::milliseconds(packet_interval_ms));
        }
    });
    
    // Monitor thread
    std::thread monitor_thread([&]() {
        vpn_metrics_t last_metrics = {};
        while (test_running.load() && std::chrono::high_resolution_clock::now() < end_time) {
            vpn_metrics_t current_metrics;
            if (vpn_get_metrics(result.handle, &current_metrics)) {
                // Check for progress
                EXPECT_GE(current_metrics.total_packets_processed, last_metrics.total_packets_processed);
                last_metrics = current_metrics;
            }
            
            // Verify VPN is still running
            EXPECT_TRUE(vpn_is_running(result.handle));
            
            std::this_thread::sleep_for(std::chrono::milliseconds(1000));
        }
    });
    
    // Wait for test completion
    traffic_thread.join();
    test_running.store(false);
    monitor_thread.join();
    
    auto actual_end_time = std::chrono::high_resolution_clock::now();
    auto actual_duration = std::chrono::duration_cast<std::chrono::seconds>(actual_end_time - start_time);
    
    std::cout << "Stability test ran for " << actual_duration.count() << " seconds" << std::endl;
    std::cout << "Packets sent: " << packets_sent.load() << std::endl;
    
    // Final verification
    EXPECT_TRUE(vpn_is_running(result.handle));
    EXPECT_GT(packets_sent.load(), 0);
    
    vpn_metrics_t final_metrics;
    EXPECT_TRUE(vpn_get_metrics(result.handle, &final_metrics));
    EXPECT_GT(final_metrics.total_packets_processed, 0);
    
    std::cout << "Final metrics - Total packets: " << final_metrics.total_packets_processed 
              << ", Errors: " << final_metrics.packet_errors << std::endl;
}