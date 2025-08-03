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
#include <arpa/inet.h>

extern "C" {
    vpn_status_t vpn_start(const vpn_config_t *config);
    vpn_status_t vpn_stop(void);
    vpn_status_t vpn_inject(const uint8_t *packet, size_t length);
    vpn_status_t vpn_get_metrics(vpn_metrics_t *metrics);
    bool vpn_is_running(void);
}

class PerformanceTest : public ::testing::Test {
protected:
    void SetUp() override {
        // Initialize VPN configuration with correct API
        memset(&config, 0, sizeof(config));
        config.utun_name = nullptr;
        config.mtu = 1500;
        config.tunnel_mtu = 1500;
        config.ipv4_enabled = true;
        config.ipv6_enabled = true;
        config.enable_nat64 = true;
        config.enable_dns_leak_protection = true;
        config.enable_ipv6_leak_protection = true;
        config.enable_kill_switch = false; // Disabled for performance testing
        config.enable_webrtc_leak_protection = true;
        config.dns_cache_size = 1024;
        config.metrics_buffer_size = 4096;
        config.reachability_monitoring = true;
        config.log_level = const_cast<char*>("ERROR"); // Minimal logging for performance
        
        // Configure DNS
        config.dns_server_count = 1;
        config.dns_servers[0] = inet_addr("8.8.8.8");
    }
    
    void TearDown() override {
        if (vpn_is_running()) {
            vpn_stop();
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
        
        // Source and destination IPs (simplified)
        packet[12] = 10; packet[13] = 0; packet[14] = 0; packet[15] = 1;  // src
        packet[16] = 8;  packet[17] = 8; packet[18] = 8; packet[19] = 8;  // dst
        
        // Fill rest with pseudo-random data
        for (size_t i = 20; i < size; i++) {
            packet[i] = (uint8_t)(i * 17 + protocol);
        }
        
        return packet;
    }
    
    vpn_config_t config;
};

TEST_F(PerformanceTest, PacketProcessingThroughput) {
    vpn_status_t result = vpn_start(&config);
    if (result == VPN_ERROR_PERMISSION) {
        GTEST_SKIP() << "Skipping test due to permission requirements";
    }
    ASSERT_EQ(result, VPN_SUCCESS);
    
    const int num_packets = 1000;
    const size_t packet_size = 1400; // Near MTU
    
    // Pre-generate packets for consistent timing
    std::vector<std::vector<uint8_t>> packets;
    packets.reserve(num_packets);
    
    for (int i = 0; i < num_packets; i++) {
        packets.push_back(generate_packet(packet_size, (i % 2) ? 6 : 17)); // TCP or UDP
    }
    
    // Measure packet injection performance
    auto start_time = std::chrono::high_resolution_clock::now();
    
    int successful_injections = 0;
    for (const auto& packet : packets) {
        if (vpn_inject(packet.data(), packet.size()) == VPN_SUCCESS) {
            successful_injections++;
        }
    }
    
    auto end_time = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end_time - start_time);
    
    // Calculate performance metrics
    double packets_per_second = (double)successful_injections / (duration.count() / 1000000.0);
    double mbps = (packets_per_second * packet_size * 8) / 1000000.0;
    
    EXPECT_GT(successful_injections, num_packets * 0.95) << "Should successfully process 95%+ of packets";
    EXPECT_GT(packets_per_second, 1000) << "Should process at least 1000 packets/second";
    
    std::cout << "Performance Results:" << std::endl;
    std::cout << "  Packets processed: " << successful_injections << "/" << num_packets << std::endl;
    std::cout << "  Duration: " << duration.count() << " microseconds" << std::endl;
    std::cout << "  Throughput: " << packets_per_second << " packets/second" << std::endl;
    std::cout << "  Bandwidth: " << mbps << " Mbps" << std::endl;
    
    vpn_stop();
}

TEST_F(PerformanceTest, ConcurrentPacketProcessing) {
    vpn_status_t result = vpn_start(&config);
    if (result == VPN_ERROR_PERMISSION) {
        GTEST_SKIP() << "Skipping test due to permission requirements";
    }
    ASSERT_EQ(result, VPN_SUCCESS);
    
    const int num_threads = 4;
    const int packets_per_thread = 250;
    
    std::atomic<int> total_processed{0};
    std::atomic<int> total_successful{0};
    std::vector<std::thread> threads;
    
    auto start_time = std::chrono::high_resolution_clock::now();
    
    auto inject_worker = [&](int thread_id) {
        for (int i = 0; i < packets_per_thread; i++) {
            auto packet = generate_packet(800 + (i % 200), 17); // Variable UDP packets
            
            total_processed.fetch_add(1);
            if (vpn_inject(packet.data(), packet.size()) == VPN_SUCCESS) {
                total_successful.fetch_add(1);
            }
            
            // Brief pause to avoid overwhelming the system
            if (i % 50 == 0) {
                std::this_thread::sleep_for(std::chrono::microseconds(100));
            }
        }
    };
    
    // Launch worker threads
    for (int i = 0; i < num_threads; i++) {
        threads.emplace_back(inject_worker, i);
    }
    
    // Wait for all threads to complete
    for (auto& t : threads) {
        t.join();
    }
    
    auto end_time = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end_time - start_time);
    
    int expected_total = num_threads * packets_per_thread;
    double success_rate = (double)total_successful.load() / total_processed.load();
    double concurrent_pps = (double)total_successful.load() / (duration.count() / 1000.0);
    
    EXPECT_EQ(total_processed.load(), expected_total);
    EXPECT_GT(success_rate, 0.90) << "Should maintain >90% success rate under concurrent load";
    EXPECT_GT(concurrent_pps, 500) << "Should maintain >500 pps under concurrent load";
    
    std::cout << "Concurrent Performance Results:" << std::endl;
    std::cout << "  Threads: " << num_threads << std::endl;
    std::cout << "  Total processed: " << total_processed.load() << std::endl;
    std::cout << "  Total successful: " << total_successful.load() << std::endl;
    std::cout << "  Success rate: " << (success_rate * 100) << "%" << std::endl;
    std::cout << "  Duration: " << duration.count() << " ms" << std::endl;
    std::cout << "  Concurrent throughput: " << concurrent_pps << " packets/second" << std::endl;
    
    vpn_stop();
}

TEST_F(PerformanceTest, MemoryPerformanceUnderLoad) {
    vpn_status_t result = vpn_start(&config);
    if (result == VPN_ERROR_PERMISSION) {
        GTEST_SKIP() << "Skipping test due to permission requirements";
    }
    ASSERT_EQ(result, VPN_SUCCESS);
    
    // Test sustained load to check for memory leaks/performance degradation
    const int num_rounds = 5;
    const int packets_per_round = 200;
    
    std::vector<double> round_performance;
    
    for (int round = 0; round < num_rounds; round++) {
        auto round_start = std::chrono::high_resolution_clock::now();
        
        int round_successful = 0;
        for (int i = 0; i < packets_per_round; i++) {
            auto packet = generate_packet(1200, (i % 3) ? 6 : 17); // Mix TCP/UDP
            
            if (vpn_inject(packet.data(), packet.size()) == VPN_SUCCESS) {
                round_successful++;
            }
        }
        
        auto round_end = std::chrono::high_resolution_clock::now();
        auto round_duration = std::chrono::duration_cast<std::chrono::microseconds>(round_end - round_start);
        
        double round_pps = (double)round_successful / (round_duration.count() / 1000000.0);
        round_performance.push_back(round_pps);
        
        std::cout << "Round " << (round + 1) << ": " << round_pps << " pps" << std::endl;
        
        // Brief pause between rounds
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
    
    // Check that performance doesn't degrade significantly over time
    double first_round_perf = round_performance[0];
    double last_round_perf = round_performance[num_rounds - 1];
    double performance_ratio = last_round_perf / first_round_perf;
    
    EXPECT_GT(performance_ratio, 0.80) << "Performance should not degrade more than 20% over sustained load";
    
    // Get final metrics to check memory usage
    vpn_metrics_t metrics;
    if (vpn_get_metrics(&metrics) == VPN_SUCCESS) {
        std::cout << "Final metrics:" << std::endl;
        std::cout << "  Total packets processed: " << metrics.total_packets_processed << std::endl;
        std::cout << "  Packet errors: " << metrics.packet_errors << std::endl;
        std::cout << "  Active connections: " << metrics.active_connections << std::endl;
    }
    
    vpn_stop();
}

TEST_F(PerformanceTest, DNSResolutionPerformance) {
    vpn_status_t result = vpn_start(&config);
    if (result == VPN_ERROR_PERMISSION) {
        GTEST_SKIP() << "Skipping test due to permission requirements";
    }
    ASSERT_EQ(result, VPN_SUCCESS);
    
    const int num_dns_queries = 100;
    
    // Create DNS query packets
    std::vector<std::vector<uint8_t>> dns_packets;
    dns_packets.reserve(num_dns_queries);
    
    for (int i = 0; i < num_dns_queries; i++) {
        std::vector<uint8_t> dns_packet = {
            // IPv4 header
            0x45, 0x00, 0x00, 0x30, 0x00, 0x01, 0x40, 0x00,
            0x40, 0x11, 0x00, 0x00, 0x0a, 0x00, 0x00, 0x01,
            0x08, 0x08, 0x08, 0x08,
            // UDP header  
            0x00, 0x35, 0x00, 0x35, 0x00, 0x1c, 0x00, 0x00,
            // DNS query
            0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x04, 't', 'e', 's',
            't', 0x03, 'c', 'o', 'm', 0x00, 0x00, 0x01, 0x00, 0x01
        };
        
        // Vary the query ID
        dns_packet[28] = (i >> 8) & 0xFF;
        dns_packet[29] = i & 0xFF;
        
        dns_packets.push_back(dns_packet);
    }
    
    // Measure DNS processing performance
    auto start_time = std::chrono::high_resolution_clock::now();
    
    int dns_successful = 0;
    for (const auto& packet : dns_packets) {
        if (vpn_inject(packet.data(), packet.size()) == VPN_SUCCESS) {
            dns_successful++;
        }
    }
    
    auto end_time = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end_time - start_time);
    
    double dns_qps = (double)dns_successful / (duration.count() / 1000000.0);
    
    EXPECT_GT(dns_successful, num_dns_queries * 0.95) << "Should successfully process 95%+ of DNS queries";
    EXPECT_GT(dns_qps, 100) << "Should process at least 100 DNS queries per second";
    
    std::cout << "DNS Performance Results:" << std::endl;
    std::cout << "  DNS queries processed: " << dns_successful << "/" << num_dns_queries << std::endl;
    std::cout << "  Duration: " << duration.count() << " microseconds" << std::endl;
    std::cout << "  DNS queries per second: " << dns_qps << std::endl;
    
    // Check DNS-specific metrics
    vpn_metrics_t metrics;
    if (vpn_get_metrics(&metrics) == VPN_SUCCESS) {
        std::cout << "  DNS queries in metrics: " << metrics.dns_queries << std::endl;
        std::cout << "  DNS cache hits: " << metrics.dns_cache_hits << std::endl;
        std::cout << "  DNS cache misses: " << metrics.dns_cache_misses << std::endl;
        
        if (metrics.dns_queries > 0) {
            double cache_hit_rate = (double)metrics.dns_cache_hits / metrics.dns_queries;
            std::cout << "  Cache hit rate: " << (cache_hit_rate * 100) << "%" << std::endl;
        }
    }
    
    vpn_stop();
}

TEST_F(PerformanceTest, PacketSizeVariabilityPerformance) {
    vpn_status_t result = vpn_start(&config);
    if (result == VPN_ERROR_PERMISSION) {
        GTEST_SKIP() << "Skipping test due to permission requirements";
    }
    ASSERT_EQ(result, VPN_SUCCESS);
    
    // Test performance with various packet sizes
    std::vector<size_t> packet_sizes = {64, 128, 256, 512, 1024, 1400};
    const int packets_per_size = 100;
    
    for (size_t packet_size : packet_sizes) {
        auto size_start = std::chrono::high_resolution_clock::now();
        
        int size_successful = 0;
        for (int i = 0; i < packets_per_size; i++) {
            auto packet = generate_packet(packet_size, 17); // UDP
            
            if (vpn_inject(packet.data(), packet.size()) == VPN_SUCCESS) {
                size_successful++;
            }
        }
        
        auto size_end = std::chrono::high_resolution_clock::now();
        auto size_duration = std::chrono::duration_cast<std::chrono::microseconds>(size_end - size_start);
        
        double size_pps = (double)size_successful / (size_duration.count() / 1000000.0);
        double size_mbps = (size_pps * packet_size * 8) / 1000000.0;
        
        std::cout << "Packet size " << packet_size << " bytes:" << std::endl;
        std::cout << "  Processed: " << size_successful << "/" << packets_per_size << std::endl;
        std::cout << "  PPS: " << size_pps << std::endl;
        std::cout << "  Mbps: " << size_mbps << std::endl;
        
        EXPECT_GT(size_successful, packets_per_size * 0.95) 
            << "Should process 95%+ of " << packet_size << " byte packets";
    }
    
    vpn_stop();
}