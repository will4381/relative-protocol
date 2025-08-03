#include <gtest/gtest.h>
#include "api/relative_vpn.h"
#include "tcp_udp/connection_manager.h"
#include "socket_bridge/bridge.h"
#include <thread>
#include <chrono>
#include <atomic>
#include <vector>
#include <random>
#include <queue>
#include <mutex>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <cstring>

class ConcurrentStressTest : public ::testing::Test {
protected:
    void SetUp() override {
        memset(&config, 0, sizeof(config));
        config.ipv4_enabled = true;
        config.ipv6_enabled = false;
        config.mtu = 1500;
        config.tunnel_mtu = 1500;
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
    }
    
    std::vector<uint8_t> generate_realistic_packet(size_t size, uint8_t protocol, uint32_t src_ip, uint32_t dst_ip, uint16_t src_port, uint16_t dst_port) {
        std::vector<uint8_t> packet(size);
        
        // IPv4 header
        packet[0] = 0x45; // Version + IHL
        packet[1] = 0x00; // ToS
        packet[2] = (size >> 8) & 0xFF;
        packet[3] = size & 0xFF;
        packet[4] = packet[5] = 0x00; // ID
        packet[6] = packet[7] = 0x40; // Flags + Fragment
        packet[8] = 64; // TTL
        packet[9] = protocol;
        packet[10] = packet[11] = 0x00; // Checksum (would be calculated)
        
        // Source IP
        packet[12] = (src_ip >> 24) & 0xFF;
        packet[13] = (src_ip >> 16) & 0xFF;
        packet[14] = (src_ip >> 8) & 0xFF;
        packet[15] = src_ip & 0xFF;
        
        // Destination IP
        packet[16] = (dst_ip >> 24) & 0xFF;
        packet[17] = (dst_ip >> 16) & 0xFF;
        packet[18] = (dst_ip >> 8) & 0xFF;
        packet[19] = dst_ip & 0xFF;
        
        // Protocol-specific headers
        if (protocol == PROTO_TCP) {
            packet[20] = (src_port >> 8) & 0xFF;
            packet[21] = src_port & 0xFF;
            packet[22] = (dst_port >> 8) & 0xFF;
            packet[23] = dst_port & 0xFF;
            // Seq, Ack, Flags would follow...
        } else if (protocol == PROTO_UDP) {
            packet[20] = (src_port >> 8) & 0xFF;
            packet[21] = src_port & 0xFF;
            packet[22] = (dst_port >> 8) & 0xFF;
            packet[23] = dst_port & 0xFF;
            uint16_t udp_len = size - 20;
            packet[24] = (udp_len >> 8) & 0xFF;
            packet[25] = udp_len & 0xFF;
            packet[26] = packet[27] = 0x00; // Checksum
        }
        
        // Fill payload with pseudo-random data
        for (size_t i = 28; i < size; i++) {
            packet[i] = (uint8_t)(i ^ src_port ^ dst_port);
        }
        
        return packet;
    }
    
    vpn_config_t config;
    vpn_result_t result = {};
};

TEST_F(ConcurrentStressTest, MassiveConnectionCreation) {
    result = vpn_start_comprehensive(&config);
    ASSERT_EQ(result.status, VPN_SUCCESS);
    
    const int total_connections = 10000;
    const int num_threads = 10;
    const int connections_per_thread = total_connections / num_threads;
    
    std::atomic<int> successful_connections{0};
    std::atomic<int> failed_connections{0};
    std::atomic<int> packets_sent{0};
    
    std::vector<std::thread> threads;
    
    auto connection_worker = [&](int thread_id) {
        std::random_device rd;
        std::mt19937 gen(rd() + thread_id);
        std::uniform_int_distribution<> port_dist(1024, 65535);
        std::uniform_int_distribution<> size_dist(64, 1400);
        std::uniform_int_distribution<> proto_dist(0, 1); // TCP or UDP
        
        for (int i = 0; i < connections_per_thread; i++) {
            uint32_t src_ip = htonl(0x0A000001 + thread_id);
            uint32_t dst_ip = htonl(0x08080800 + (i % 256));
            uint16_t src_port = port_dist(gen);
            uint16_t dst_port = (proto_dist(gen) == 0) ? 80 : 53;
            uint8_t protocol = (dst_port == 80) ? PROTO_TCP : PROTO_UDP;
            
            // Generate multiple packets per connection
            for (int pkt = 0; pkt < 5; pkt++) {
                int packet_size = size_dist(gen);
                auto packet_data = generate_realistic_packet(packet_size, protocol, src_ip, dst_ip, src_port, dst_port);
                
                packet_info_t packet = {};
                packet.data = packet_data.data();
                packet.length = packet_data.size();
                packet.flow.ip_version = 4;
                packet.flow.protocol = protocol;
                packet.flow.src_ip.v4.addr = src_ip;
                packet.flow.dst_ip.v4.addr = dst_ip;
                packet.flow.src_port = src_port;
                packet.flow.dst_port = dst_port;
                packet.timestamp_ns = clock_gettime_nsec_np(CLOCK_MONOTONIC);
                
                if (vpn_inject_packet_comprehensive(result.handle, &packet)) {
                    packets_sent.fetch_add(1);
                    if (pkt == 0) successful_connections.fetch_add(1);
                } else {
                    if (pkt == 0) failed_connections.fetch_add(1);
                }
                
                // Brief delay to simulate realistic traffic timing
                std::this_thread::sleep_for(std::chrono::microseconds(100));
            }
        }
    };
    
    auto start_time = std::chrono::high_resolution_clock::now();
    
    // Start all threads
    for (int i = 0; i < num_threads; i++) {
        threads.emplace_back(connection_worker, i);
    }
    
    // Wait for completion
    for (auto& t : threads) {
        t.join();
    }
    
    auto end_time = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::seconds>(end_time - start_time);
    
    std::cout << "Stress test completed in " << duration.count() << " seconds" << std::endl;
    std::cout << "Successful connections: " << successful_connections.load() << std::endl;
    std::cout << "Failed connections: " << failed_connections.load() << std::endl;
    std::cout << "Total packets sent: " << packets_sent.load() << std::endl;
    
    vpn_metrics_t metrics;
    EXPECT_TRUE(vpn_get_metrics_comprehensive(result.handle, &metrics));
    std::cout << "VPN processed: " << metrics.total_packets_processed << " packets" << std::endl;
    std::cout << "TCP connections: " << metrics.tcp_connections << std::endl;
    std::cout << "UDP sessions: " << metrics.udp_sessions << std::endl;
    
    // Expect reasonable success rate even under stress
    EXPECT_GT(successful_connections.load(), total_connections * 0.7); // 70% success rate
    EXPECT_GT(packets_sent.load(), 0);
    EXPECT_TRUE(vpn_is_running_comprehensive(result.handle));
}

TEST_F(ConcurrentStressTest, HighFrequencyPacketBurst) {
    result = vpn_start_comprehensive(&config);
    ASSERT_EQ(result.status, VPN_SUCCESS);
    
    const int burst_size = 1000;
    const int num_bursts = 50;
    const int num_threads = 8;
    
    std::atomic<int> total_packets_sent{0};
    std::atomic<int> bursts_completed{0};
    
    std::vector<std::thread> threads;
    
    auto burst_worker = [&](int thread_id) {
        std::random_device rd;
        std::mt19937 gen(rd() + thread_id);
        std::uniform_int_distribution<> size_dist(64, 1400);
        
        for (int burst = 0; burst < num_bursts / num_threads; burst++) {
            // Generate burst of packets rapidly
            std::vector<std::vector<uint8_t>> packet_batch;
            std::vector<packet_info_t> packet_infos;
            
            packet_batch.reserve(burst_size);
            packet_infos.reserve(burst_size);
            
            // Pre-generate packet data
            for (int i = 0; i < burst_size; i++) {
                uint32_t src_ip = htonl(0x0A000001 + thread_id);
                uint32_t dst_ip = htonl(0x08080800 + (i % 256));
                uint16_t src_port = 1000 + thread_id * 1000 + i;
                uint16_t dst_port = 53;
                
                packet_batch.push_back(generate_realistic_packet(size_dist(gen), PROTO_UDP, src_ip, dst_ip, src_port, dst_port));
                
                packet_info_t pkt = {};
                pkt.data = packet_batch.back().data();
                pkt.length = packet_batch.back().size();
                pkt.flow.ip_version = 4;
                pkt.flow.protocol = PROTO_UDP;
                pkt.flow.src_ip.v4.addr = src_ip;
                pkt.flow.dst_ip.v4.addr = dst_ip;
                pkt.flow.src_port = src_port;
                pkt.flow.dst_port = dst_port;
                pkt.timestamp_ns = clock_gettime_nsec_np(CLOCK_MONOTONIC);
                
                packet_infos.push_back(pkt);
            }
            
            // Send burst as fast as possible
            int sent_in_burst = 0;
            for (int i = 0; i < burst_size; i++) {
                if (vpn_inject_packet_comprehensive(result.handle, &packet_infos[i])) {
                    sent_in_burst++;
                }
            }
            
            total_packets_sent.fetch_add(sent_in_burst);
            bursts_completed.fetch_add(1);
            
            // Brief pause between bursts
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
        }
    };
    
    auto start_time = std::chrono::high_resolution_clock::now();
    
    // Start burst workers
    for (int i = 0; i < num_threads; i++) {
        threads.emplace_back(burst_worker, i);
    }
    
    // Wait for completion
    for (auto& t : threads) {
        t.join();
    }
    
    auto end_time = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end_time - start_time);
    
    double packets_per_second = (double)total_packets_sent.load() / (duration.count() / 1000.0);
    
    std::cout << "Burst stress test completed in " << duration.count() << "ms" << std::endl;
    std::cout << "Bursts completed: " << bursts_completed.load() << "/" << num_bursts << std::endl;
    std::cout << "Total packets sent: " << total_packets_sent.load() << std::endl;
    std::cout << "Packet rate: " << packets_per_second << " packets/sec" << std::endl;
    
    vpn_metrics_t metrics;
    EXPECT_TRUE(vpn_get_metrics_comprehensive(result.handle, &metrics));
    std::cout << "VPN processed: " << metrics.total_packets_processed << " packets" << std::endl;
    
    EXPECT_EQ(bursts_completed.load(), num_bursts);
    EXPECT_GT(total_packets_sent.load(), num_bursts * burst_size * 0.8); // 80% success rate
    EXPECT_GT(packets_per_second, 5000); // At least 5K packets/sec
}

TEST_F(ConcurrentStressTest, LongRunningStability) {
    result = vpn_start_comprehensive(&config);
    ASSERT_EQ(result.status, VPN_SUCCESS);
    
    const auto test_duration = std::chrono::minutes(2); // 2 minute stress test
    const int num_traffic_threads = 6;
    const int num_monitor_threads = 2;
    
    std::atomic<bool> test_running{true};
    std::atomic<int> total_packets{0};
    std::atomic<int> errors_detected{0};
    
    std::vector<std::thread> threads;
    
    // Traffic generation threads
    auto traffic_generator = [&](int thread_id) {
        std::random_device rd;
        std::mt19937 gen(rd() + thread_id);
        std::uniform_int_distribution<> interval_dist(1, 50); // 1-50ms between packets
        std::uniform_int_distribution<> size_dist(64, 1200);
        std::uniform_int_distribution<> proto_dist(0, 1);
        
        int packet_id = 0;
        while (test_running.load()) {
            uint32_t src_ip = htonl(0x0A000001 + thread_id);
            uint32_t dst_ip = htonl(0x08080800 + (packet_id % 256));
            uint16_t src_port = 1000 + thread_id * 1000 + (packet_id % 1000);
            uint8_t protocol = (proto_dist(gen) == 0) ? PROTO_TCP : PROTO_UDP;
            uint16_t dst_port = (protocol == PROTO_TCP) ? 80 : 53;
            
            auto packet_data = generate_realistic_packet(size_dist(gen), protocol, src_ip, dst_ip, src_port, dst_port);
            
            packet_info_t packet = {};
            packet.data = packet_data.data();
            packet.length = packet_data.size();
            packet.flow.ip_version = 4;
            packet.flow.protocol = protocol;
            packet.flow.src_ip.v4.addr = src_ip;
            packet.flow.dst_ip.v4.addr = dst_ip;
            packet.flow.src_port = src_port;
            packet.flow.dst_port = dst_port;
            packet.timestamp_ns = clock_gettime_nsec_np(CLOCK_MONOTONIC);
            
            if (vpn_inject_packet_comprehensive(result.handle, &packet)) {
                total_packets.fetch_add(1);
            } else {
                errors_detected.fetch_add(1);
            }
            
            packet_id++;
            std::this_thread::sleep_for(std::chrono::milliseconds(interval_dist(gen)));
        }
    };
    
    // Monitoring threads
    auto monitor = [&](int monitor_id) {
        vpn_metrics_t last_metrics = {};
        
        while (test_running.load()) {
            if (!vpn_is_running_comprehensive(result.handle)) {
                errors_detected.fetch_add(1000); // Major error
                break;
            }
            
            vpn_metrics_t current_metrics;
            if (vpn_get_metrics_comprehensive(result.handle, &current_metrics)) {
                // Check for progress and consistency
                if (current_metrics.total_packets_processed < last_metrics.total_packets_processed) {
                    errors_detected.fetch_add(1); // Metrics regression
                }
                
                last_metrics = current_metrics;
            } else {
                errors_detected.fetch_add(1);
            }
            
            std::this_thread::sleep_for(std::chrono::seconds(1));
        }
    };
    
    auto start_time = std::chrono::high_resolution_clock::now();
    
    // Start traffic threads
    for (int i = 0; i < num_traffic_threads; i++) {
        threads.emplace_back(traffic_generator, i);
    }
    
    // Start monitor threads
    for (int i = 0; i < num_monitor_threads; i++) {
        threads.emplace_back(monitor, i);
    }
    
    // Run for specified duration
    std::this_thread::sleep_for(test_duration);
    test_running.store(false);
    
    // Wait for all threads to complete
    for (auto& t : threads) {
        t.join();
    }
    
    auto end_time = std::chrono::high_resolution_clock::now();
    auto actual_duration = std::chrono::duration_cast<std::chrono::seconds>(end_time - start_time);
    
    std::cout << "Long-running stress test completed after " << actual_duration.count() << " seconds" << std::endl;
    std::cout << "Total packets sent: " << total_packets.load() << std::endl;
    std::cout << "Errors detected: " << errors_detected.load() << std::endl;
    
    vpn_metrics_t final_metrics;
    EXPECT_TRUE(vpn_get_metrics_comprehensive(result.handle, &final_metrics));
    
    std::cout << "Final VPN metrics:" << std::endl;
    std::cout << "  Processed: " << final_metrics.total_packets_processed << " packets" << std::endl;
    std::cout << "  TCP connections: " << final_metrics.tcp_connections << std::endl;
    std::cout << "  UDP sessions: " << final_metrics.udp_sessions << std::endl;
    std::cout << "  Errors: " << final_metrics.packet_errors << std::endl;
    std::cout << "  Uptime: " << final_metrics.uptime_seconds << " seconds" << std::endl;
    
    // Stability checks
    EXPECT_TRUE(vpn_is_running_comprehensive(result.handle));
    EXPECT_GT(total_packets.load(), 1000); // Should have sent substantial traffic
    EXPECT_LT(errors_detected.load(), total_packets.load() * 0.01); // < 1% error rate
    EXPECT_GT(final_metrics.total_packets_processed, 0);
    EXPECT_GE(final_metrics.uptime_seconds, actual_duration.count() - 5); // Allow 5s variance
}

TEST_F(ConcurrentStressTest, MemoryPressureTest) {
    result = vpn_start_comprehensive(&config);
    ASSERT_EQ(result.status, VPN_SUCCESS);
    
    const int num_memory_stress_threads = 4;
    const int allocations_per_thread = 1000;
    const int packets_per_allocation = 50;
    
    std::atomic<int> allocations_completed{0};
    std::atomic<int> packets_sent{0};
    
    std::vector<std::thread> threads;
    
    auto memory_stress_worker = [&](int thread_id) {
        std::random_device rd;
        std::mt19937 gen(rd() + thread_id);
        std::uniform_int_distribution<> size_dist(100, 2000);
        
        for (int alloc = 0; alloc < allocations_per_thread; alloc++) {
            // Allocate memory for packet buffers
            std::vector<std::vector<uint8_t>> packet_buffers;
            packet_buffers.reserve(packets_per_allocation);
            
            // Generate packets with varying sizes
            for (int i = 0; i < packets_per_allocation; i++) {
                uint32_t src_ip = htonl(0x0A000001 + thread_id);
                uint32_t dst_ip = htonl(0x08080800 + alloc);
                uint16_t src_port = 1000 + thread_id * 1000 + i;
                uint16_t dst_port = 53;
                
                packet_buffers.push_back(generate_realistic_packet(size_dist(gen), PROTO_UDP, src_ip, dst_ip, src_port, dst_port));
            }
            
            // Send all packets in this allocation
            for (int i = 0; i < packets_per_allocation; i++) {
                packet_info_t packet = {};
                packet.data = packet_buffers[i].data();
                packet.length = packet_buffers[i].size();
                packet.flow.ip_version = 4;
                packet.flow.protocol = PROTO_UDP;
                packet.flow.src_ip.v4.addr = htonl(0x0A000001 + thread_id);
                packet.flow.dst_ip.v4.addr = htonl(0x08080800 + alloc);
                packet.flow.src_port = 1000 + thread_id * 1000 + i;
                packet.flow.dst_port = 53;
                packet.timestamp_ns = clock_gettime_nsec_np(CLOCK_MONOTONIC);
                
                if (vpn_inject_packet_comprehensive(result.handle, &packet)) {
                    packets_sent.fetch_add(1);
                }
            }
            
            allocations_completed.fetch_add(1);
            
            // Brief pause to let system handle memory pressure
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
        }
    };
    
    auto start_time = std::chrono::high_resolution_clock::now();
    
    // Start memory stress threads
    for (int i = 0; i < num_memory_stress_threads; i++) {
        threads.emplace_back(memory_stress_worker, i);
    }
    
    // Wait for completion
    for (auto& t : threads) {
        t.join();
    }
    
    auto end_time = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::seconds>(end_time - start_time);
    
    std::cout << "Memory pressure test completed in " << duration.count() << " seconds" << std::endl;
    std::cout << "Allocations completed: " << allocations_completed.load() << std::endl;
    std::cout << "Packets sent: " << packets_sent.load() << std::endl;
    
    vpn_metrics_t metrics;
    EXPECT_TRUE(vpn_get_metrics_comprehensive(result.handle, &metrics));
    std::cout << "VPN processed: " << metrics.total_packets_processed << " packets" << std::endl;
    
    // Memory stress should not break the VPN
    EXPECT_TRUE(vpn_is_running_comprehensive(result.handle));
    EXPECT_EQ(allocations_completed.load(), num_memory_stress_threads * allocations_per_thread);
    EXPECT_GT(packets_sent.load(), 0);
    EXPECT_GT(metrics.total_packets_processed, 0);
}

TEST_F(ConcurrentStressTest, ConfigurationChangeUnderLoad) {
    result = vpn_start_comprehensive(&config);
    ASSERT_EQ(result.status, VPN_SUCCESS);
    
    const int traffic_duration_seconds = 30;
    const int config_changes = 10;
    
    std::atomic<bool> traffic_running{true};
    std::atomic<int> packets_sent{0};
    std::atomic<int> config_changes_applied{0};
    
    // Traffic thread
    std::thread traffic_thread([&]() {
        std::random_device rd;
        std::mt19937 gen(rd());
        std::uniform_int_distribution<> size_dist(64, 1200);
        
        int packet_id = 0;
        while (traffic_running.load()) {
            auto packet_data = generate_realistic_packet(size_dist(gen), PROTO_UDP, 
                htonl(0x0A000001), htonl(0x08080808), 12345, 53);
            
            packet_info_t packet = {};
            packet.data = packet_data.data();
            packet.length = packet_data.size();
            packet.flow.ip_version = 4;
            packet.flow.protocol = PROTO_UDP;
            packet.flow.src_ip.v4.addr = htonl(0x0A000001);
            packet.flow.dst_ip.v4.addr = htonl(0x08080808);
            packet.flow.src_port = 12345;
            packet.flow.dst_port = 53;
            packet.timestamp_ns = clock_gettime_nsec_np(CLOCK_MONOTONIC);
            
            if (vpn_inject_packet_comprehensive(result.handle, &packet)) {
                packets_sent.fetch_add(1);
            }
            
            packet_id++;
            std::this_thread::sleep_for(std::chrono::milliseconds(5));
        }
    });
    
    // Configuration change thread
    std::thread config_thread([&]() {
        vpn_config_t test_config = config;
        
        for (int i = 0; i < config_changes; i++) {
            // Alternate between different configurations
            if (i % 2 == 0) {
                test_config.tunnel_mtu = 1280;
                test_config.enable_dns_leak_protection = false;
            } else {
                test_config.tunnel_mtu = 1500;
                test_config.enable_dns_leak_protection = true;
            }
            
            if (vpn_update_config_comprehensive(result.handle, &test_config)) {
                config_changes_applied.fetch_add(1);
            }
            
            std::this_thread::sleep_for(std::chrono::seconds(traffic_duration_seconds / config_changes));
        }
    });
    
    // Run for specified duration
    std::this_thread::sleep_for(std::chrono::seconds(traffic_duration_seconds));
    traffic_running.store(false);
    
    traffic_thread.join();
    config_thread.join();
    
    std::cout << "Configuration change under load test completed" << std::endl;
    std::cout << "Packets sent: " << packets_sent.load() << std::endl;
    std::cout << "Configuration changes applied: " << config_changes_applied.load() << "/" << config_changes << std::endl;
    
    vpn_metrics_t metrics;
    EXPECT_TRUE(vpn_get_metrics_comprehensive(result.handle, &metrics));
    std::cout << "VPN processed: " << metrics.total_packets_processed << " packets" << std::endl;
    
    // VPN should remain stable during config changes
    EXPECT_TRUE(vpn_is_running_comprehensive(result.handle));
    EXPECT_GT(packets_sent.load(), 1000);
    EXPECT_GT(config_changes_applied.load(), config_changes / 2); // At least half should succeed
}

// Entry point for running stress tests independently
int main(int argc, char **argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}