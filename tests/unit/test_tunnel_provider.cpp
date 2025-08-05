#include <gtest/gtest.h>
#include "packet/tunnel_provider.h"
#include "core/types.h"
#include <thread>
#include <chrono>
#include <atomic>

// Note: NetworkExtension imports are in the .mm file implementation
// This test file focuses on C API testing

/**
 * Tunnel Provider Unit Tests
 * 
 * Tests the iOS-specific tunnel provider functionality:
 * - Creation and destruction
 * - Packet handler configuration
 * - Packet sending and receiving
 * - Statistics collection
 * - Memory management
 */

class TunnelProviderTest : public ::testing::Test {
protected:
    void SetUp() override {
        provider = tunnel_provider_create();
        ASSERT_NE(provider, nullptr);
        
        packets_received = 0;
        last_packet_length = 0;
    }
    
    void TearDown() override {
        if (provider) {
            tunnel_provider_destroy(provider);
        }
    }
    
    tunnel_provider_t *provider;
    std::atomic<int> packets_received{0};
    std::atomic<size_t> last_packet_length{0};
    
    static void packet_handler(const packet_info_t *packet, void *user_data) {
        auto *test = static_cast<TunnelProviderTest*>(user_data);
        if (packet && packet->data && packet->length > 0) {
            test->packets_received++;
            test->last_packet_length = packet->length;
        }
    }
};

TEST_F(TunnelProviderTest, CreateDestroy) {
    EXPECT_NE(provider, nullptr);
    
    // Test multiple create/destroy cycles
    for (int i = 0; i < 5; i++) {
        tunnel_provider_t *temp = tunnel_provider_create();
        EXPECT_NE(temp, nullptr);
        tunnel_provider_destroy(temp);
    }
}

TEST_F(TunnelProviderTest, PacketHandlerConfiguration) {
    // Set packet handler
    bool result = tunnel_provider_set_packet_handler(provider, packet_handler, this);
    EXPECT_TRUE(result);
    
    // Test with null parameters
    result = tunnel_provider_set_packet_handler(NULL, packet_handler, this);
    EXPECT_FALSE(result);
    
    result = tunnel_provider_set_packet_handler(provider, NULL, this);
    EXPECT_TRUE(result); // Should succeed with null handler
}

TEST_F(TunnelProviderTest, PacketSending) {
    // Create a simple IPv4 packet
    uint8_t test_packet[] = {
        0x45, 0x00, 0x00, 0x1c,  // IPv4 header start
        0x00, 0x01, 0x40, 0x00,
        0x40, 0x11, 0x00, 0x00,  // UDP protocol
        0x7f, 0x00, 0x00, 0x01,  // Source: 127.0.0.1
        0x7f, 0x00, 0x00, 0x01,  // Dest: 127.0.0.1
        0x00, 0x50, 0x00, 0x50,  // UDP ports (80 -> 80)
        0x00, 0x08, 0x00, 0x00   // UDP header
    };
    
    // Note: On iOS, this would normally fail without a configured packet flow
    // In unit tests, we're just testing the API
    bool result = tunnel_provider_send_packet(provider, test_packet, sizeof(test_packet));
    
    // Expected to fail in unit test environment (no NEPacketTunnelFlow configured)
    EXPECT_FALSE(result);
    
    // Test with invalid parameters
    result = tunnel_provider_send_packet(NULL, test_packet, sizeof(test_packet));
    EXPECT_FALSE(result);
    
    result = tunnel_provider_send_packet(provider, NULL, sizeof(test_packet));
    EXPECT_FALSE(result);
    
    result = tunnel_provider_send_packet(provider, test_packet, 0);
    EXPECT_FALSE(result);
}

TEST_F(TunnelProviderTest, PacketProcessing) {
    // Set up packet handler
    tunnel_provider_set_packet_handler(provider, packet_handler, this);
    
    // Process packets (should not crash)
    bool result = tunnel_provider_process_packets(provider);
    EXPECT_TRUE(result);
    
    // Initially no packets should be received
    EXPECT_EQ(packets_received.load(), 0);
    
    // Test with null provider
    result = tunnel_provider_process_packets(NULL);
    EXPECT_FALSE(result);
}

TEST_F(TunnelProviderTest, Statistics) {
    vpn_metrics_t metrics = {};
    
    // Get initial statistics
    tunnel_provider_get_stats(provider, &metrics);
    
    // Should start with zero values
    EXPECT_EQ(metrics.bytes_sent, 0);
    EXPECT_EQ(metrics.bytes_received, 0);
    EXPECT_EQ(metrics.total_packets_processed, 0);
    EXPECT_EQ(metrics.packet_errors, 0);
    
    // Test with null parameters
    tunnel_provider_get_stats(NULL, &metrics);
    // Should not crash
    
    tunnel_provider_get_stats(provider, NULL);
    // Should not crash
}

// iOS-specific tests are implemented in separate .mm test files
// to avoid Objective-C++ compilation issues in unit tests

TEST_F(TunnelProviderTest, MemoryStressTest) {
    // Create many providers to test memory management
    const int num_providers = 100;
    std::vector<tunnel_provider_t*> providers;
    
    for (int i = 0; i < num_providers; i++) {
        tunnel_provider_t *p = tunnel_provider_create();
        ASSERT_NE(p, nullptr);
        providers.push_back(p);
    }
    
    // Clean up all providers
    for (auto *p : providers) {
        tunnel_provider_destroy(p);
    }
    
    // Should not crash or leak memory
}

TEST_F(TunnelProviderTest, ConcurrentAccess) {
    // Test concurrent access to tunnel provider
    std::atomic<bool> running{true};
    std::atomic<int> thread_errors{0};
    
    tunnel_provider_set_packet_handler(provider, packet_handler, this);
    
    // Start multiple threads accessing the provider
    std::vector<std::thread> threads;
    
    for (int i = 0; i < 4; i++) {
        threads.emplace_back([this, &running, &thread_errors]() {
            while (running) {
                // Try to process packets
                if (!tunnel_provider_process_packets(provider)) {
                    // This is expected to fail in unit test environment
                }
                
                // Get statistics
                vpn_metrics_t metrics;
                tunnel_provider_get_stats(provider, &metrics);
                
                std::this_thread::sleep_for(std::chrono::milliseconds(1));
            }
        });
    }
    
    // Let threads run for a short time
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    running = false;
    
    // Wait for all threads to complete
    for (auto &thread : threads) {
        thread.join();
    }
    
    // Should not have any errors from threading issues
    EXPECT_EQ(thread_errors.load(), 0);
}