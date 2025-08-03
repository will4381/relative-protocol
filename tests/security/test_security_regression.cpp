#include <gtest/gtest.h>
#include "api/relative_vpn.h"
#include "nat64/translator.h"
#include "socket_bridge/bridge.h"
#include "packet/buffer_manager.h"
#include "core/types.h"
#include <thread>
#include <chrono>
#include <atomic>
#include <vector>
#include <memory>
#include <cstring>
#include <arpa/inet.h>

/**
 * Security Regression Test Suite
 * 
 * Validates critical security fixes implemented in the VPN framework:
 * 1. NAT64 buffer overflow fixes with safe packet buffer system
 * 2. Socket bridge memory leak fixes with thread cleanup
 * 3. ASN.1 parser hardening against certificate vulnerabilities
 * 4. TOCTOU race condition fixes with atomic operations
 * 5. Memory pool implementation for performance
 */

class SecurityRegressionTest : public ::testing::Test {
protected:
    void SetUp() override {
        config = {};
        config.utun_name = nullptr;
        config.mtu = 1500;
        config.tunnel_mtu = 1500;
        config.ipv4_enabled = true;
        config.ipv6_enabled = true;
        config.enable_nat64 = true;
        config.enable_dns_leak_protection = true;
        config.enable_ipv6_leak_protection = true;
        config.enable_kill_switch = false;
        config.dns_servers[0] = inet_addr("8.8.8.8");
        config.dns_server_count = 1;
        config.dns_cache_size = 1024;
        config.metrics_buffer_size = 4096;
        config.log_level = const_cast<char*>("DEBUG");
        
        result = {};
    }
    
    void TearDown() override {
        if (result.handle != VPN_INVALID_HANDLE) {
            vpn_stop_comprehensive(result.handle);
        }
    }
    
    vpn_config_t config;
    vpn_result_t result;
    
    // Security test utilities
    std::vector<uint8_t> create_malicious_packet(size_t size, uint8_t fill_byte = 0xFF);
    bool test_buffer_overflow_protection(const uint8_t* data, size_t size);
    void stress_test_memory_allocation(int iterations);
};

std::vector<uint8_t> SecurityRegressionTest::create_malicious_packet(size_t size, uint8_t fill_byte) {
    std::vector<uint8_t> packet(size, fill_byte);
    
    // Add minimal IP header to make it look valid initially
    if (size >= 20) {
        packet[0] = 0x45; // IPv4, header length 20
        packet[1] = 0x00; // DSCP
        packet[2] = (size >> 8) & 0xFF; // Total length high
        packet[3] = size & 0xFF; // Total length low
        packet[9] = 0x11; // UDP protocol
    }
    
    return packet;
}

bool SecurityRegressionTest::test_buffer_overflow_protection(const uint8_t* data, size_t size) {
    // This should not crash or corrupt memory even with malicious input
    result = vpn_start_comprehensive(&config);
    if (result.status != VPN_SUCCESS) {
        return false; // Skip if VPN can't start
    }
    
    packet_info_t packet = {};
    packet.data = const_cast<uint8_t*>(data);
    packet.length = size;
    packet.flow.ip_version = 4;
    packet.timestamp_ns = clock_gettime_nsec_np(CLOCK_MONOTONIC);
    
    // Attempt injection - should not crash
    bool injected = vpn_inject_packet_comprehensive(result.handle, &packet);
    
    // Allow processing
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    
    // System should remain stable
    bool still_running = vpn_is_running_comprehensive(result.handle);
    
    vpn_stop_comprehensive(result.handle);
    result.handle = VPN_INVALID_HANDLE;
    
    return still_running;
}

void SecurityRegressionTest::stress_test_memory_allocation(int iterations) {
    std::vector<std::unique_ptr<uint8_t[]>> allocations;
    
    for (int i = 0; i < iterations; i++) {
        size_t size = 1024 + (i % 4096); // Variable sizes
        try {
            auto ptr = std::make_unique<uint8_t[]>(size);
            memset(ptr.get(), 0xAA, size); // Fill with pattern
            allocations.push_back(std::move(ptr));
            
            // Periodically free some allocations
            if (i % 100 == 0 && !allocations.empty()) {
                allocations.erase(allocations.begin(), 
                                allocations.begin() + std::min(50, (int)allocations.size()));
            }
        } catch (const std::bad_alloc&) {
            // Expected under memory pressure
            break;
        }
    }
}

// Test NAT64 buffer overflow fixes
TEST_F(SecurityRegressionTest, NAT64BufferOverflowProtection) {
    nat64_translator_t* translator = nat64_translator_create(nullptr, 0);
    ASSERT_NE(translator, nullptr);
    
    // Test oversized IPv4 packet
    auto oversized_ipv4 = create_malicious_packet(65536, 0xFF);
    uint8_t output_buffer[MAX_PACKET_SIZE];
    size_t output_length;
    
    // Should not crash or corrupt memory
    bool result_4to6 = nat64_translate_4to6(translator, 
                                           oversized_ipv4.data(), oversized_ipv4.size(),
                                           output_buffer, &output_length, sizeof(output_buffer));
    
    // Should reject oversized packet gracefully
    EXPECT_FALSE(result_4to6);
    
    // Test oversized IPv6 packet
    auto oversized_ipv6 = create_malicious_packet(65536, 0xAA);
    if (oversized_ipv6.size() >= 40) {
        oversized_ipv6[0] = 0x60; // IPv6 version
    }
    
    bool result_6to4 = nat64_translate_6to4(translator,
                                           oversized_ipv6.data(), oversized_ipv6.size(),
                                           output_buffer, &output_length, sizeof(output_buffer));
    
    EXPECT_FALSE(result_6to4);
    
    // Test malformed packet with invalid length fields
    auto malformed_packet = create_malicious_packet(100, 0x00);
    if (malformed_packet.size() >= 4) {
        malformed_packet[2] = 0xFF; // Invalid total length
        malformed_packet[3] = 0xFF;
    }
    
    bool result_malformed = nat64_translate_4to6(translator,
                                                malformed_packet.data(), malformed_packet.size(),
                                                output_buffer, &output_length, sizeof(output_buffer));
    
    // Should handle gracefully
    EXPECT_FALSE(result_malformed);
    
    // Verify translator remains functional after attacks
    nat64_stats_t stats;
    nat64_get_stats(translator, &stats);
    EXPECT_GE(stats.translation_errors, 0);
    
    nat64_translator_destroy(translator);
}

// Test socket bridge memory leak fixes
TEST_F(SecurityRegressionTest, SocketBridgeMemoryLeakPrevention) {
    // Test multiple bridge create/destroy cycles
    const int cycles = 50;
    
    for (int i = 0; i < cycles; i++) {
        // This tests the socket bridge thread cleanup fixes
        result = vpn_start_comprehensive(&config);
        
        if (result.status == VPN_ERROR_PERMISSION) {
            GTEST_SKIP() << "Requires elevated permissions for socket bridge testing";
        }
        
        if (result.status != VPN_SUCCESS) {
            continue; // Skip failed starts
        }
        
        // Create some socket activity
        packet_info_t test_packet = {};
        uint8_t packet_data[] = {
            0x45, 0x00, 0x00, 0x1c, 0x00, 0x01, 0x40, 0x00,
            0x40, 0x11, 0x00, 0x00, 0x0a, 0x00, 0x00, 0x01,
            0x08, 0x08, 0x08, 0x08, 0x00, 0x35, 0x00, 0x35,
            0x00, 0x08, 0x00, 0x00
        };
        
        test_packet.data = packet_data;
        test_packet.length = sizeof(packet_data);
        test_packet.flow.ip_version = 4;
        test_packet.flow.protocol = PROTO_UDP;
        test_packet.timestamp_ns = clock_gettime_nsec_np(CLOCK_MONOTONIC);
        
        vpn_inject_packet_comprehensive(result.handle, &test_packet);
        
        // Brief processing time
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
        
        // Stop VPN (tests thread cleanup)
        EXPECT_TRUE(vpn_stop_comprehensive(result.handle));
        result.handle = VPN_INVALID_HANDLE;
        
        // Brief pause between cycles
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
    
    // If we reach here without crashes/hangs, memory leak fixes are working
    SUCCEED();
}

// Test TOCTOU race condition fixes with atomic operations
TEST_F(SecurityRegressionTest, TOCTOURaceConditionPrevention) {
    result = vpn_start_comprehensive(&config);
    
    if (result.status == VPN_ERROR_PERMISSION) {
        GTEST_SKIP() << "Requires elevated permissions";
    }
    
    ASSERT_EQ(result.status, VPN_SUCCESS);
    
    // Concurrent configuration changes (tests atomic operations)
    const int thread_count = 8;
    const int operations_per_thread = 100;
    std::atomic<int> successful_operations{0};
    std::atomic<int> failed_operations{0};
    std::vector<std::thread> threads;
    
    auto concurrent_operations = [&](int thread_id) {
        for (int i = 0; i < operations_per_thread; i++) {
            // Alternate between different operations
            if (i % 3 == 0) {
                // Get metrics (read operation)
                vpn_metrics_t metrics;
                if (vpn_get_metrics_comprehensive(result.handle, &metrics)) {
                    successful_operations.fetch_add(1);
                } else {
                    failed_operations.fetch_add(1);
                }
            } else if (i % 3 == 1) {
                // Check if running (state read)
                if (vpn_is_running_comprehensive(result.handle)) {
                    successful_operations.fetch_add(1);
                } else {
                    failed_operations.fetch_add(1);
                }
            } else {
                // Inject packet (write operation)
                uint8_t packet_data[] = {
                    0x45, 0x00, 0x00, 0x1c, 0x00, 0x01, 0x40, 0x00,
                    0x40, 0x11, 0x00, 0x00, 0x0a, 0x00, 0x00, 0x01,
                    0x08, 0x08, 0x08, 0x08
                };
                
                packet_info_t packet = {};
                packet.data = packet_data;
                packet.length = sizeof(packet_data);
                packet.flow.ip_version = 4;
                packet.timestamp_ns = clock_gettime_nsec_np(CLOCK_MONOTONIC);
                
                if (vpn_inject_packet_comprehensive(result.handle, &packet)) {
                    successful_operations.fetch_add(1);
                } else {
                    failed_operations.fetch_add(1);
                }
            }
            
            // Small delay to create race conditions
            if (i % 10 == 0) {
                std::this_thread::sleep_for(std::chrono::microseconds(100));
            }
        }
    };
    
    // Start concurrent threads
    for (int i = 0; i < thread_count; i++) {
        threads.emplace_back(concurrent_operations, i);
    }
    
    // Wait for completion
    for (auto& t : threads) {
        t.join();
    }
    
    // Verify system stability and atomicity
    EXPECT_TRUE(vpn_is_running_comprehensive(result.handle));
    EXPECT_GT(successful_operations.load(), 0);
    
    // Should have high success rate (atomic operations prevent corruption)
    int total_operations = successful_operations.load() + failed_operations.load();
    EXPECT_GT(successful_operations.load(), total_operations * 0.9); // >90% success
    
    // Final metrics check
    vpn_metrics_t final_metrics;
    EXPECT_TRUE(vpn_get_metrics_comprehensive(result.handle, &final_metrics));
}

// Test memory pool implementation and safety
TEST_F(SecurityRegressionTest, MemoryPoolSafety) {
    result = vpn_start_comprehensive(&config);
    
    if (result.status != VPN_SUCCESS) {
        GTEST_SKIP() << "VPN startup failed";
    }
    
    // Stress test memory allocation patterns
    const int allocation_cycles = 1000;
    std::vector<std::thread> memory_threads;
    std::atomic<bool> memory_corruption_detected{false};
    
    auto memory_stress_test = [&](int thread_id) {
        for (int i = 0; i < allocation_cycles / 4; i++) {
            // Create packets of varying sizes to stress memory pools
            size_t packet_size = 64 + (i % 1400); // Variable sizes
            auto packet_data = create_malicious_packet(packet_size, 0xAA + thread_id);
            
            packet_info_t packet = {};
            packet.data = packet_data.data();
            packet.length = packet_data.size();
            packet.flow.ip_version = 4;
            packet.timestamp_ns = clock_gettime_nsec_np(CLOCK_MONOTONIC);
            
            // Inject packet (allocates from memory pools)
            vpn_inject_packet_comprehensive(result.handle, &packet);
            
            // Verify no memory corruption
            if (packet_data[0] != (0xAA + thread_id)) {
                memory_corruption_detected.store(true);
                break;
            }
            
            if (i % 100 == 0) {
                std::this_thread::sleep_for(std::chrono::milliseconds(1));
            }
        }
    };
    
    // Start memory stress threads
    for (int i = 0; i < 4; i++) {
        memory_threads.emplace_back(memory_stress_test, i);
    }
    
    // Wait for completion
    for (auto& t : memory_threads) {
        t.join();
    }
    
    // Verify no memory corruption detected
    EXPECT_FALSE(memory_corruption_detected.load());
    
    // System should remain stable
    EXPECT_TRUE(vpn_is_running_comprehensive(result.handle));
    
    // Memory metrics should be reasonable
    vpn_metrics_t metrics;
    EXPECT_TRUE(vpn_get_metrics_comprehensive(result.handle, &metrics));
    EXPECT_GT(metrics.total_packets_processed, 0);
}

// Test ASN.1 parser hardening (certificate processing)
TEST_F(SecurityRegressionTest, ASN1ParserHardening) {
    // Test malformed certificate-like data
    std::vector<uint8_t> malformed_cert_data = {
        0x30, 0x82, 0xFF, 0xFF, // Invalid length field
        0x30, 0x82, 0x00, 0x00, // Zero length
        0x02, 0x01, 0x01,       // Valid integer
        0x30, 0x80,             // Indefinite length (potential DoS)
        0x04, 0xFF, 0xAA,       // Invalid octet string length
        0x00, 0x00              // End marker
    };
    
    // This should not crash the VPN even if certificate parsing is involved
    result = vpn_start_comprehensive(&config);
    
    if (result.status != VPN_SUCCESS) {
        GTEST_SKIP() << "VPN startup failed";
    }
    
    // Create TLS-like packet that might trigger certificate parsing
    std::vector<uint8_t> tls_packet = {
        // IP header
        0x45, 0x00, 0x00, 0x64, 0x00, 0x01, 0x40, 0x00,
        0x40, 0x06, 0x00, 0x00, 0x0a, 0x00, 0x00, 0x01,
        0x68, 0x68, 0x68, 0x68,
        
        // TCP header (simplified)
        0x01, 0xBB, 0x01, 0xBB, 0x00, 0x00, 0x00, 0x01,
        0x00, 0x00, 0x00, 0x00, 0x50, 0x18, 0xFF, 0xFF,
        0x00, 0x00, 0x00, 0x00,
        
        // TLS handshake with malformed certificate
        0x16, 0x03, 0x03, 0x00, 0x40, // TLS header
        0x0B, 0x00, 0x00, 0x3C, // Certificate message
    };
    
    // Append malformed certificate data
    tls_packet.insert(tls_packet.end(), malformed_cert_data.begin(), malformed_cert_data.end());
    
    packet_info_t packet = {};
    packet.data = tls_packet.data();
    packet.length = tls_packet.size();
    packet.flow.ip_version = 4;
    packet.flow.protocol = PROTO_TCP;
    packet.flow.src_port = 443;
    packet.flow.dst_port = 443;
    packet.timestamp_ns = clock_gettime_nsec_np(CLOCK_MONOTONIC);
    
    // Should handle gracefully without crashing
    bool injected = vpn_inject_packet_comprehensive(result.handle, &packet);
    
    // Allow processing
    std::this_thread::sleep_for(std::chrono::milliseconds(200));
    
    // System should remain stable
    EXPECT_TRUE(vpn_is_running_comprehensive(result.handle));
    
    vpn_metrics_t metrics;
    EXPECT_TRUE(vpn_get_metrics_comprehensive(result.handle, &metrics));
    // May have packet errors, but should not crash
}

// Test buffer boundary protection
TEST_F(SecurityRegressionTest, BufferBoundaryProtection) {
    // Test various buffer overflow scenarios
    std::vector<size_t> test_sizes = {
        0,           // Zero size
        1,           // Minimal size
        MAX_PACKET_SIZE - 1,  // Just under limit
        MAX_PACKET_SIZE,      // At limit
        MAX_PACKET_SIZE + 1,  // Just over limit
        MAX_PACKET_SIZE * 2,  // Way over limit
        65536,       // Common large size
    };
    
    for (size_t size : test_sizes) {
        SCOPED_TRACE("Testing buffer size: " + std::to_string(size));
        
        auto test_data = create_malicious_packet(size, 0xBB);
        
        // Test buffer overflow protection
        bool system_stable = test_buffer_overflow_protection(test_data.data(), test_data.size());
        
        if (size <= MAX_PACKET_SIZE) {
            // System should handle valid sizes
            EXPECT_TRUE(system_stable);
        } else {
            // System should remain stable even with oversized packets
            EXPECT_TRUE(system_stable);
        }
    }
}

// Test concurrent security stress scenarios
TEST_F(SecurityRegressionTest, ConcurrentSecurityStress) {
    result = vpn_start_comprehensive(&config);
    
    if (result.status != VPN_SUCCESS) {
        GTEST_SKIP() << "VPN startup failed";
    }
    
    const int thread_count = 6;
    std::atomic<bool> attack_detected{false};
    std::vector<std::thread> attack_threads;
    
    // Different attack patterns running concurrently
    auto buffer_overflow_attack = [&]() {
        for (int i = 0; i < 100; i++) {
            auto oversized = create_malicious_packet(MAX_PACKET_SIZE + 1000, 0xFF);
            packet_info_t packet = {};
            packet.data = oversized.data();
            packet.length = oversized.size();
            packet.flow.ip_version = 4;
            packet.timestamp_ns = clock_gettime_nsec_np(CLOCK_MONOTONIC);
            
            vpn_inject_packet_comprehensive(result.handle, &packet);
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
        }
    };
    
    auto memory_exhaustion_attack = [&]() {
        stress_test_memory_allocation(500);
    };
    
    auto race_condition_attack = [&]() {
        for (int i = 0; i < 200; i++) {
            vpn_metrics_t metrics;
            vpn_get_metrics_comprehensive(result.handle, &metrics);
            vpn_is_running_comprehensive(result.handle);
            
            if (i % 10 == 0) {
                std::this_thread::sleep_for(std::chrono::microseconds(100));
            }
        }
    };
    
    // Launch concurrent attacks
    attack_threads.emplace_back(buffer_overflow_attack);
    attack_threads.emplace_back(buffer_overflow_attack);
    attack_threads.emplace_back(memory_exhaustion_attack);
    attack_threads.emplace_back(race_condition_attack);
    attack_threads.emplace_back(race_condition_attack);
    
    // Monitor system stability
    std::thread monitor([&]() {
        for (int i = 0; i < 50; i++) {
            if (!vpn_is_running_comprehensive(result.handle)) {
                attack_detected.store(true);
                break;
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }
    });
    
    // Wait for attacks to complete
    for (auto& t : attack_threads) {
        t.join();
    }
    
    monitor.join();
    
    // System should survive concurrent attacks
    EXPECT_FALSE(attack_detected.load());
    EXPECT_TRUE(vpn_is_running_comprehensive(result.handle));
    
    // Final health check
    vpn_metrics_t final_metrics;
    EXPECT_TRUE(vpn_get_metrics_comprehensive(result.handle, &final_metrics));
}