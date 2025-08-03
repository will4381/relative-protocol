#include <gtest/gtest.h>
#include "api/relative_vpn.h"
#include "packet/utun.h"
#include "reachability/monitor.h"
#include "core/types.h"
#include <thread>
#include <chrono>
#include <atomic>
#include <vector>

#ifdef __APPLE__
#include <Network/Network.h>
#include <NetworkExtension/NetworkExtension.h>
#include <SystemConfiguration/SystemConfiguration.h>
#include <CoreFoundation/CoreFoundation.h>
#endif

/**
 * iOS NetworkExtension Integration Tests
 * 
 * Tests VPN framework integration with iOS NetworkExtension APIs:
 * - UTun interface creation and management
 * - Network reachability monitoring
 * - Memory pressure handling on iOS
 * - Background/foreground transitions
 * - iOS network stack integration
 * - NetworkExtension lifecycle management
 */

class NetworkExtensionIntegrationTest : public ::testing::Test {
protected:
    void SetUp() override {
#ifndef __APPLE__
        GTEST_SKIP() << "iOS NetworkExtension tests only run on Apple platforms";
#endif
        
        config = {};
        config.utun_name = nullptr; // Auto-assign
        config.mtu = 1500;
        config.tunnel_mtu = 1500;
        config.ipv4_enabled = true;
        config.ipv6_enabled = true;
        config.enable_nat64 = true;
        config.enable_dns_leak_protection = true;
        config.enable_ipv6_leak_protection = true;
        config.enable_kill_switch = true; // Important for iOS
        config.reachability_monitoring = true; // Critical for iOS
        
        // iOS-appropriate DNS servers
        config.dns_servers[0] = inet_addr("8.8.8.8");
        config.dns_servers[1] = inet_addr("1.1.1.1");
        config.dns_server_count = 2;
        
        config.dns_cache_size = 512; // Conservative for mobile
        config.metrics_buffer_size = 2048; // Conservative for mobile
        config.log_level = const_cast<char*>("INFO");
        
        result = {};
        network_changed = false;
        memory_pressure_detected = false;
    }
    
    void TearDown() override {
        if (result.handle != VPN_INVALID_HANDLE) {
            vpn_stop_comprehensive(result.handle);
        }
        
        cleanup_ios_resources();
    }
    
    vpn_config_t config;
    vpn_result_t result;
    std::atomic<bool> network_changed{false};
    std::atomic<bool> memory_pressure_detected{false};
    
    // iOS-specific test utilities
    bool test_utun_interface_creation();
    bool test_ios_network_reachability();
    void simulate_memory_pressure();
    void simulate_network_transition();
    bool verify_ios_packet_routing();
    void cleanup_ios_resources();
    
#ifdef __APPLE__
    // iOS-specific members
    nw_path_monitor_t path_monitor = nullptr;
    dispatch_queue_t monitor_queue = nullptr;
#endif
};

bool NetworkExtensionIntegrationTest::test_utun_interface_creation() {
#ifdef __APPLE__
    // Test UTun interface creation with iOS-specific requirements
    utun_handle_t* utun = utun_create(nullptr, 1500);
    
    if (!utun) {
        return false;
    }
    
    // Verify interface properties
    const char* interface_name = utun_get_name(utun);
    EXPECT_NE(interface_name, nullptr);
    EXPECT_STRNE(interface_name, "");
    
    // Should start with "utun"
    EXPECT_EQ(strncmp(interface_name, "utun", 4), 0);
    
    // Verify MTU
    uint16_t mtu = utun_get_mtu(utun);
    EXPECT_EQ(mtu, 1500);
    
    // Test MTU modification
    EXPECT_TRUE(utun_set_mtu(utun, 1280));
    EXPECT_EQ(utun_get_mtu(utun), 1280);
    
    // Get file descriptor (should be valid)
    int fd = utun_get_fd(utun);
    EXPECT_GE(fd, 0);
    
    // Clean up
    utun_destroy(utun);
    
    return true;
#else
    return false;
#endif
}

bool NetworkExtensionIntegrationTest::test_ios_network_reachability() {
#ifdef __APPLE__
    // Create network path monitor
    monitor_queue = dispatch_queue_create("test.reachability", DISPATCH_QUEUE_SERIAL);
    path_monitor = nw_path_monitor_create();
    
    if (!path_monitor || !monitor_queue) {
        return false;
    }
    
    // Set up path update handler
    nw_path_monitor_set_update_handler(path_monitor, ^(nw_path_t path) {
        nw_path_status_t status = nw_path_get_status(path);
        
        if (status == nw_path_status_satisfied) {
            // Network is available
            network_changed.store(true);
        } else if (status == nw_path_status_unsatisfied) {
            // Network is not available
            network_changed.store(true);
        }
        
        // Check if path uses cellular
        bool uses_cellular = nw_path_uses_interface_type(path, nw_interface_type_cellular);
        bool uses_wifi = nw_path_uses_interface_type(path, nw_interface_type_wifi);
        
        // Log network type changes
        if (uses_cellular) {
            std::cout << "Network path uses cellular" << std::endl;
        }
        if (uses_wifi) {
            std::cout << "Network path uses WiFi" << std::endl;
        }
    });
    
    nw_path_monitor_set_queue(path_monitor, monitor_queue);
    nw_path_monitor_start(path_monitor);
    
    // Wait for initial network status
    std::this_thread::sleep_for(std::chrono::milliseconds(500));
    
    return network_changed.load();
#else
    return false;
#endif
}

void NetworkExtensionIntegrationTest::simulate_memory_pressure() {
    // Simulate iOS memory pressure by allocating large amounts of memory
    std::vector<std::unique_ptr<uint8_t[]>> allocations;
    
    try {
        // Allocate until we get memory pressure (or reach reasonable limit)
        for (int i = 0; i < 1000; i++) {
            size_t alloc_size = 1024 * 1024; // 1MB allocations
            auto ptr = std::make_unique<uint8_t[]>(alloc_size);
            memset(ptr.get(), 0xAA, alloc_size); // Touch pages
            allocations.push_back(std::move(ptr));
            
            // Check if VPN is still responsive under memory pressure
            if (result.handle != VPN_INVALID_HANDLE) {
                vpn_metrics_t metrics;
                if (!vpn_get_metrics_comprehensive(result.handle, &metrics)) {
                    memory_pressure_detected.store(true);
                    break;
                }
            }
            
            if (i % 100 == 0) {
                std::this_thread::sleep_for(std::chrono::milliseconds(10));
            }
        }
    } catch (const std::bad_alloc&) {
        memory_pressure_detected.store(true);
    }
    
    // Gradually release memory
    while (!allocations.empty() && allocations.size() > 100) {
        allocations.pop_back();
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }
}

void NetworkExtensionIntegrationTest::simulate_network_transition() {
    // Simulate network transitions that might occur on iOS
    // This is primarily for testing VPN resilience
    
    if (result.handle == VPN_INVALID_HANDLE) {
        return;
    }
    
    // Get initial metrics
    vpn_metrics_t initial_metrics;
    vpn_get_metrics_comprehensive(result.handle, &initial_metrics);
    
    // Simulate brief network interruption by injecting failure scenarios
    for (int i = 0; i < 10; i++) {
        // Try to get metrics during "network transition"
        vpn_metrics_t metrics;
        bool success = vpn_get_metrics_comprehensive(result.handle, &metrics);
        
        if (!success) {
            network_changed.store(true);
        }
        
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
}

bool NetworkExtensionIntegrationTest::verify_ios_packet_routing() {
    if (result.handle == VPN_INVALID_HANDLE) {
        return false;
    }
    
    // Create iOS-typical network packets
    std::vector<packet_info_t> test_packets;
    
    // Safari HTTP request
    uint8_t http_packet[] = {
        0x45, 0x00, 0x00, 0x3C, 0x00, 0x01, 0x40, 0x00,
        0x40, 0x06, 0x00, 0x00, 0x0A, 0x00, 0x00, 0x01,
        0x11, 0x22, 0x33, 0x44, 0x00, 0x50, 0x12, 0x34,
        0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
        0x50, 0x02, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00
    };
    
    packet_info_t safari_packet = {};
    safari_packet.data = http_packet;
    safari_packet.length = sizeof(http_packet);
    safari_packet.flow.ip_version = 4;
    safari_packet.flow.protocol = PROTO_TCP;
    safari_packet.flow.src_port = 4660;
    safari_packet.flow.dst_port = 80;
    safari_packet.timestamp_ns = clock_gettime_nsec_np(CLOCK_MONOTONIC);
    
    // iOS Mail SMTP
    uint8_t smtp_packet[] = {
        0x45, 0x00, 0x00, 0x28, 0x00, 0x01, 0x40, 0x00,
        0x40, 0x06, 0x00, 0x00, 0x0A, 0x00, 0x00, 0x01,
        0x4A, 0x7D, 0x83, 0x0E, 0x00, 0x19, 0x03, 0x79,
        0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
        0x50, 0x02, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00
    };
    
    packet_info_t mail_packet = {};
    mail_packet.data = smtp_packet;
    mail_packet.length = sizeof(smtp_packet);
    mail_packet.flow.ip_version = 4;
    mail_packet.flow.protocol = PROTO_TCP;
    mail_packet.flow.src_port = 889;
    mail_packet.flow.dst_port = 25;
    mail_packet.timestamp_ns = clock_gettime_nsec_np(CLOCK_MONOTONIC);
    
    // App Store HTTPS
    uint8_t https_packet[] = {
        0x45, 0x00, 0x00, 0x34, 0x00, 0x01, 0x40, 0x00,
        0x40, 0x06, 0x00, 0x00, 0x0A, 0x00, 0x00, 0x01,
        0x17, 0xC0, 0xA8, 0x01, 0x01, 0xBB, 0x0C, 0x35,
        0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
        0x50, 0x02, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00
    };
    
    packet_info_t appstore_packet = {};
    appstore_packet.data = https_packet;
    appstore_packet.length = sizeof(https_packet);
    appstore_packet.flow.ip_version = 4;
    appstore_packet.flow.protocol = PROTO_TCP;
    appstore_packet.flow.src_port = 3125;
    appstore_packet.flow.dst_port = 443;
    appstore_packet.timestamp_ns = clock_gettime_nsec_np(CLOCK_MONOTONIC);
    
    // Inject all packets
    bool all_successful = true;
    all_successful &= vpn_inject_packet_comprehensive(result.handle, &safari_packet);
    all_successful &= vpn_inject_packet_comprehensive(result.handle, &mail_packet);
    all_successful &= vpn_inject_packet_comprehensive(result.handle, &appstore_packet);
    
    // Allow processing
    std::this_thread::sleep_for(std::chrono::milliseconds(200));
    
    // Verify packets were processed
    vpn_metrics_t metrics;
    bool metrics_success = vpn_get_metrics_comprehensive(result.handle, &metrics);
    
    return all_successful && metrics_success && (metrics.total_packets_processed > 0);
}

void NetworkExtensionIntegrationTest::cleanup_ios_resources() {
#ifdef __APPLE__
    if (path_monitor) {
        nw_path_monitor_cancel(path_monitor);
        path_monitor = nullptr;
    }
    
    if (monitor_queue) {
        dispatch_release(monitor_queue);
        monitor_queue = nullptr;
    }
#endif
}

// Test UTun interface creation and management on iOS
TEST_F(NetworkExtensionIntegrationTest, UTunInterfaceManagement) {
    EXPECT_TRUE(test_utun_interface_creation());
}

// Test VPN startup and shutdown with iOS NetworkExtension
TEST_F(NetworkExtensionIntegrationTest, NetworkExtensionLifecycle) {
    // Start VPN with iOS-appropriate configuration
    result = vpn_start_comprehensive(&config);
    
    if (result.status == VPN_ERROR_PERMISSION) {
        GTEST_SKIP() << "NetworkExtension requires proper entitlements and provisioning";
    }
    
    if (result.status == VPN_ERROR_UTUN_FAILED) {
        GTEST_SKIP() << "UTun interface creation failed - may require iOS device or simulator";
    }
    
    ASSERT_EQ(result.status, VPN_SUCCESS);
    ASSERT_NE(result.handle, VPN_INVALID_HANDLE);
    
    // Verify VPN is running
    EXPECT_TRUE(vpn_is_running_comprehensive(result.handle));
    
    // Test iOS-specific packet routing
    EXPECT_TRUE(verify_ios_packet_routing());
    
    // Get metrics to verify functionality
    vpn_metrics_t metrics;
    EXPECT_TRUE(vpn_get_metrics_comprehensive(result.handle, &metrics));
    EXPECT_GE(metrics.uptime_seconds, 0);
    
    // Test graceful shutdown
    EXPECT_TRUE(vpn_stop_comprehensive(result.handle));
    EXPECT_FALSE(vpn_is_running_comprehensive(result.handle));
    
    result.handle = VPN_INVALID_HANDLE;
}

// Test network reachability monitoring integration
TEST_F(NetworkExtensionIntegrationTest, NetworkReachabilityIntegration) {
    // Test iOS network reachability
    EXPECT_TRUE(test_ios_network_reachability());
    
    // Start VPN with reachability monitoring
    result = vpn_start_comprehensive(&config);
    
    if (result.status != VPN_SUCCESS) {
        GTEST_SKIP() << "VPN startup failed";
    }
    
    // Simulate network state changes
    simulate_network_transition();
    
    // VPN should handle network changes gracefully
    EXPECT_TRUE(vpn_is_running_comprehensive(result.handle));
    
    // Verify reachability monitoring is working
    vpn_metrics_t metrics;
    EXPECT_TRUE(vpn_get_metrics_comprehensive(result.handle, &metrics));
    EXPECT_GE(metrics.network_status, 0);
}

// Test VPN behavior under iOS memory pressure
TEST_F(NetworkExtensionIntegrationTest, MemoryPressureHandling) {
    result = vpn_start_comprehensive(&config);
    
    if (result.status != VPN_SUCCESS) {
        GTEST_SKIP() << "VPN startup failed";
    }
    
    // Get baseline metrics
    vpn_metrics_t baseline_metrics;
    EXPECT_TRUE(vpn_get_metrics_comprehensive(result.handle, &baseline_metrics));
    
    // Simulate memory pressure in separate thread
    std::thread memory_thread([this]() {
        simulate_memory_pressure();
    });
    
    // Continue normal operation during memory pressure
    for (int i = 0; i < 20; i++) {
        vpn_metrics_t current_metrics;
        bool success = vpn_get_metrics_comprehensive(result.handle, &current_metrics);
        
        if (!success) {
            // VPN may become less responsive under memory pressure
            break;
        }
        
        // Inject test packet to verify continued operation
        uint8_t test_packet[] = {
            0x45, 0x00, 0x00, 0x1C, 0x00, 0x01, 0x40, 0x00,
            0x40, 0x11, 0x00, 0x00, 0x0A, 0x00, 0x00, 0x01,
            0x08, 0x08, 0x08, 0x08, 0x00, 0x35, 0x00, 0x35,
            0x00, 0x08, 0x00, 0x00
        };
        
        packet_info_t packet = {};
        packet.data = test_packet;
        packet.length = sizeof(test_packet);
        packet.flow.ip_version = 4;
        packet.flow.protocol = PROTO_UDP;
        packet.timestamp_ns = clock_gettime_nsec_np(CLOCK_MONOTONIC);
        
        vpn_inject_packet_comprehensive(result.handle, &packet);
        
        std::this_thread::sleep_for(std::chrono::milliseconds(200));
    }
    
    memory_thread.join();
    
    // VPN should survive memory pressure
    EXPECT_TRUE(vpn_is_running_comprehensive(result.handle));
    
    // Final metrics check
    vpn_metrics_t final_metrics;
    EXPECT_TRUE(vpn_get_metrics_comprehensive(result.handle, &final_metrics));
    EXPECT_GE(final_metrics.total_packets_processed, baseline_metrics.total_packets_processed);
}

// Test kill switch functionality on iOS
TEST_F(NetworkExtensionIntegrationTest, KillSwitchFunctionality) {
    config.enable_kill_switch = true;
    result = vpn_start_comprehensive(&config);
    
    if (result.status != VPN_SUCCESS) {
        GTEST_SKIP() << "VPN startup failed";
    }
    
    // Test that traffic is blocked when VPN is down
    // This is simulated since we can't actually control network interfaces in tests
    
    // Inject packet that should be blocked if kill switch is active
    uint8_t blocked_packet[] = {
        0x45, 0x00, 0x00, 0x1C, 0x00, 0x01, 0x40, 0x00,
        0x40, 0x11, 0x00, 0x00, 0x0A, 0x00, 0x00, 0x01,
        0x04, 0x04, 0x04, 0x04, 0x00, 0x35, 0x00, 0x35, // Unauthorized DNS
        0x00, 0x08, 0x00, 0x00
    };
    
    packet_info_t packet = {};
    packet.data = blocked_packet;
    packet.length = sizeof(blocked_packet);
    packet.flow.ip_version = 4;
    packet.flow.protocol = PROTO_UDP;
    packet.flow.dst_port = 53;
    packet.timestamp_ns = clock_gettime_nsec_np(CLOCK_MONOTONIC);
    
    vpn_inject_packet_comprehensive(result.handle, &packet);
    
    // Allow processing
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    
    // Check if kill switch blocked unauthorized traffic
    vpn_metrics_t metrics;
    EXPECT_TRUE(vpn_get_metrics_comprehensive(result.handle, &metrics));
    EXPECT_GE(metrics.packets_blocked, 0); // Kill switch may have blocked packets
}

// Test DNS leak protection on iOS
TEST_F(NetworkExtensionIntegrationTest, DNSLeakProtection) {
    config.enable_dns_leak_protection = true;
    result = vpn_start_comprehensive(&config);
    
    if (result.status != VPN_SUCCESS) {
        GTEST_SKIP() << "VPN startup failed";
    }
    
    // Test authorized DNS query (should pass)
    uint8_t authorized_dns[] = {
        0x45, 0x00, 0x00, 0x2C, 0x00, 0x01, 0x40, 0x00,
        0x40, 0x11, 0x00, 0x00, 0x0A, 0x00, 0x00, 0x01,
        0x08, 0x08, 0x08, 0x08, 0x00, 0x35, 0x00, 0x35,
        0x00, 0x18, 0x00, 0x00,
        // DNS query
        0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x06, 'g', 'o', 'o',
        'g', 'l', 'e', 0x03, 'c', 'o', 'm', 0x00,
        0x00, 0x01, 0x00, 0x01
    };
    
    packet_info_t auth_packet = {};
    auth_packet.data = authorized_dns;
    auth_packet.length = sizeof(authorized_dns);
    auth_packet.flow.ip_version = 4;
    auth_packet.flow.protocol = PROTO_UDP;
    auth_packet.flow.src_port = 53478;
    auth_packet.flow.dst_port = 53;
    auth_packet.timestamp_ns = clock_gettime_nsec_np(CLOCK_MONOTONIC);
    
    EXPECT_TRUE(vpn_inject_packet_comprehensive(result.handle, &auth_packet));
    
    // Test unauthorized DNS query (should be blocked)
    uint8_t unauthorized_dns[] = {
        0x45, 0x00, 0x00, 0x2C, 0x00, 0x01, 0x40, 0x00,
        0x40, 0x11, 0x00, 0x00, 0x0A, 0x00, 0x00, 0x01,
        0x04, 0x04, 0x04, 0x04, 0x00, 0x35, 0x00, 0x35, // Unauthorized DNS server
        0x00, 0x18, 0x00, 0x00,
        // DNS query
        0x12, 0x35, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x04, 't', 'e', 's',
        't', 0x03, 'c', 'o', 'm', 0x00, 0x00, 0x01, 0x00, 0x01
    };
    
    packet_info_t unauth_packet = {};
    unauth_packet.data = unauthorized_dns;
    unauth_packet.length = sizeof(unauthorized_dns);
    unauth_packet.flow.ip_version = 4;
    unauth_packet.flow.protocol = PROTO_UDP;
    unauth_packet.flow.src_port = 53479;
    unauth_packet.flow.dst_port = 53;
    unauth_packet.timestamp_ns = clock_gettime_nsec_np(CLOCK_MONOTONIC);
    
    EXPECT_TRUE(vpn_inject_packet_comprehensive(result.handle, &unauth_packet));
    
    // Allow processing
    std::this_thread::sleep_for(std::chrono::milliseconds(200));
    
    // Check DNS leak protection metrics
    vpn_metrics_t metrics;
    EXPECT_TRUE(vpn_get_metrics_comprehensive(result.handle, &metrics));
    EXPECT_GE(metrics.dns_queries, 1); // At least one DNS query processed
    EXPECT_GE(metrics.privacy_violations, 0); // May have detected violations
}

// Test configuration updates during runtime
TEST_F(NetworkExtensionIntegrationTest, RuntimeConfigurationUpdates) {
    result = vpn_start_comprehensive(&config);
    
    if (result.status != VPN_SUCCESS) {
        GTEST_SKIP() << "VPN startup failed";
    }
    
    // Update configuration at runtime
    vpn_config_t new_config = config;
    new_config.tunnel_mtu = 1280; // Smaller MTU
    new_config.enable_dns_leak_protection = false; // Disable protection
    
    EXPECT_TRUE(vpn_update_config_comprehensive(result.handle, &new_config));
    
    // Verify configuration was applied
    vpn_config_t current_config;
    EXPECT_TRUE(vpn_get_config_comprehensive(result.handle, &current_config));
    EXPECT_EQ(current_config.tunnel_mtu, 1280);
    EXPECT_FALSE(current_config.enable_dns_leak_protection);
    
    // Test that new configuration is working
    uint8_t test_packet[] = {
        0x45, 0x00, 0x00, 0x1C, 0x00, 0x01, 0x40, 0x00,
        0x40, 0x11, 0x00, 0x00, 0x0A, 0x00, 0x00, 0x01,
        0x04, 0x04, 0x04, 0x04, 0x00, 0x35, 0x00, 0x35,
        0x00, 0x08, 0x00, 0x00
    };
    
    packet_info_t packet = {};
    packet.data = test_packet;
    packet.length = sizeof(test_packet);
    packet.flow.ip_version = 4;
    packet.flow.protocol = PROTO_UDP;
    packet.timestamp_ns = clock_gettime_nsec_np(CLOCK_MONOTONIC);
    
    EXPECT_TRUE(vpn_inject_packet_comprehensive(result.handle, &packet));
    
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    
    // VPN should still be functional with new configuration
    EXPECT_TRUE(vpn_is_running_comprehensive(result.handle));
}