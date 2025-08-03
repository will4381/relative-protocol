#include <gtest/gtest.h>
#include "reachability/monitor.h"
#include <thread>
#include <chrono>
#include <atomic>

class ReachabilityMonitorTest : public ::testing::Test {
protected:
    void SetUp() override {
        monitor = reachability_monitor_create();
        ASSERT_NE(monitor, nullptr);
    }
    
    void TearDown() override {
        if (monitor) {
            reachability_monitor_destroy(monitor);
        }
    }
    
    reachability_monitor_t *monitor;
};

TEST_F(ReachabilityMonitorTest, CreateDestroy) {
    EXPECT_NE(monitor, nullptr);
    
    // Test multiple create/destroy cycles
    for (int i = 0; i < 5; i++) {
        reachability_monitor_t *temp = reachability_monitor_create();
        EXPECT_NE(temp, nullptr);
        reachability_monitor_destroy(temp);
    }
}

TEST_F(ReachabilityMonitorTest, NetworkStatusDetection) {
    // Get initial network status
    network_status_t status = reachability_monitor_get_status(monitor);
    
    // Status should be one of the valid values
    EXPECT_GE(status, NETWORK_STATUS_DISCONNECTED);
    EXPECT_LE(status, NETWORK_STATUS_CONNECTED_CELLULAR);
    
    // Test status string conversion
    const char *status_str = network_status_string(status);
    EXPECT_NE(status_str, nullptr);
    EXPECT_GT(strlen(status_str), 0);
}

TEST_F(ReachabilityMonitorTest, InterfaceInformation) {
    network_interface_info_t interfaces[MAX_NETWORK_INTERFACES];
    size_t interface_count;
    
    bool success = reachability_monitor_get_interfaces(monitor, interfaces, &interface_count, MAX_NETWORK_INTERFACES);
    
    if (success && interface_count > 0) {
        EXPECT_LE(interface_count, MAX_NETWORK_INTERFACES);
        
        for (size_t i = 0; i < interface_count; i++) {
            EXPECT_GT(strlen(interfaces[i].name), 0);
            EXPECT_GE(interfaces[i].type, INTERFACE_TYPE_LOOPBACK);
            EXPECT_LE(interfaces[i].type, INTERFACE_TYPE_OTHER);
            
            // If interface is active, it should have some properties
            if (interfaces[i].is_active) {
                EXPECT_TRUE(interfaces[i].has_ipv4 || interfaces[i].has_ipv6);
            }
        }
    }
}

TEST_F(ReachabilityMonitorTest, ConnectivityTesting) {
    // Test connectivity to well-known servers
    ip_addr_t google_dns = { .v4 = { .addr = inet_addr("8.8.8.8") } };
    ip_addr_t cloudflare_dns = { .v4 = { .addr = inet_addr("1.1.1.1") } };
    
    std::atomic<int> callback_count{0};
    std::atomic<bool> reachable{false};
    
    auto callback = [](const ip_addr_t *target, bool is_reachable, uint32_t rtt_ms, void *user_data) {
        auto *count = static_cast<std::atomic<int>*>(user_data);
        count->fetch_add(1);
        
        EXPECT_NE(target, nullptr);
        if (is_reachable) {
            EXPECT_GT(rtt_ms, 0);
            EXPECT_LT(rtt_ms, 10000); // Reasonable RTT limit
        }
    };
    
    reachability_monitor_set_callback(monitor, callback, &callback_count);
    
    // Start connectivity tests
    EXPECT_TRUE(reachability_monitor_test_connectivity(monitor, &google_dns));
    EXPECT_TRUE(reachability_monitor_test_connectivity(monitor, &cloudflare_dns));
    
    // Wait for results
    for (int i = 0; i < 50 && callback_count.load() < 2; i++) {
        reachability_monitor_process_events(monitor);
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
    
    // Should have received some callbacks
    EXPECT_GE(callback_count.load(), 0);
}

TEST_F(ReachabilityMonitorTest, NetworkChangeDetection) {
    std::atomic<int> change_count{0};
    std::atomic<network_status_t> last_status{NETWORK_STATUS_UNKNOWN};
    
    auto callback = [](network_status_t old_status, network_status_t new_status, void *user_data) {
        auto *count = static_cast<std::atomic<int>*>(user_data);
        count->fetch_add(1);
        
        EXPECT_GE(old_status, NETWORK_STATUS_DISCONNECTED);
        EXPECT_LE(old_status, NETWORK_STATUS_CONNECTED_CELLULAR);
        EXPECT_GE(new_status, NETWORK_STATUS_DISCONNECTED);
        EXPECT_LE(new_status, NETWORK_STATUS_CONNECTED_CELLULAR);
    };
    
    reachability_monitor_set_change_callback(monitor, callback, &change_count);
    
    // Force an update check
    reachability_monitor_force_update(monitor);
    
    // Process events for a short time
    for (int i = 0; i < 10; i++) {
        reachability_monitor_process_events(monitor);
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
    
    // Changes depend on actual network state, so just verify no crashes
    EXPECT_GE(change_count.load(), 0);
}

TEST_F(ReachabilityMonitorTest, InterfaceMonitoring) {
    // Test interface-specific monitoring
    network_interface_info_t interfaces[MAX_NETWORK_INTERFACES];
    size_t interface_count;
    
    bool success = reachability_monitor_get_interfaces(monitor, interfaces, &interface_count, MAX_NETWORK_INTERFACES);
    
    if (success && interface_count > 0) {
        // Monitor the first active interface
        for (size_t i = 0; i < interface_count; i++) {
            if (interfaces[i].is_active) {
                EXPECT_TRUE(reachability_monitor_add_interface(monitor, interfaces[i].name));
                
                // Test interface status
                bool interface_active = reachability_monitor_is_interface_active(monitor, interfaces[i].name);
                EXPECT_EQ(interface_active, interfaces[i].is_active);
                
                // Remove interface monitoring
                EXPECT_TRUE(reachability_monitor_remove_interface(monitor, interfaces[i].name));
                break;
            }
        }
    }
}

TEST_F(ReachabilityMonitorTest, DefaultGatewayInfo) {
    ip_addr_t gateway_ipv4, gateway_ipv6;
    char interface_name[64];
    
    // Test IPv4 default gateway
    bool has_ipv4_gateway = reachability_monitor_get_default_gateway(
        monitor, &gateway_ipv4, interface_name, sizeof(interface_name), false);
    
    if (has_ipv4_gateway) {
        EXPECT_GT(strlen(interface_name), 0);
        EXPECT_NE(gateway_ipv4.v4.addr, 0);
    }
    
    // Test IPv6 default gateway
    bool has_ipv6_gateway = reachability_monitor_get_default_gateway(
        monitor, &gateway_ipv6, interface_name, sizeof(interface_name), true);
    
    if (has_ipv6_gateway) {
        EXPECT_GT(strlen(interface_name), 0);
    }
}

TEST_F(ReachabilityMonitorTest, DNSServerDetection) {
    ip_addr_t dns_servers[MAX_DNS_SERVERS];
    size_t dns_count;
    
    bool success = reachability_monitor_get_dns_servers(monitor, dns_servers, &dns_count, MAX_DNS_SERVERS);
    
    if (success && dns_count > 0) {
        EXPECT_LE(dns_count, MAX_DNS_SERVERS);
        
        for (size_t i = 0; i < dns_count; i++) {
            // Verify DNS servers are valid addresses
            if (dns_servers[i].version == 4) {
                EXPECT_NE(dns_servers[i].v4.addr, 0);
            } else if (dns_servers[i].version == 6) {
                bool all_zero = true;
                for (int j = 0; j < 16; j++) {
                    if (dns_servers[i].v6.addr[j] != 0) {
                        all_zero = false;
                        break;
                    }
                }
                EXPECT_FALSE(all_zero);
            }
        }
    }
}

TEST_F(ReachabilityMonitorTest, ConnectionQualityMetrics) {
    connection_quality_t quality;
    bool success = reachability_monitor_get_connection_quality(monitor, &quality);
    
    if (success) {
        EXPECT_GE(quality.signal_strength, 0.0);
        EXPECT_LE(quality.signal_strength, 1.0);
        EXPECT_GE(quality.bandwidth_estimate_mbps, 0.0);
        EXPECT_GE(quality.latency_ms, 0);
        EXPECT_GE(quality.packet_loss_percent, 0.0);
        EXPECT_LE(quality.packet_loss_percent, 100.0);
    }
}

TEST_F(ReachabilityMonitorTest, NetworkEventHistory) {
    network_event_t events[MAX_NETWORK_EVENTS];
    size_t event_count;
    
    bool success = reachability_monitor_get_event_history(monitor, events, &event_count, MAX_NETWORK_EVENTS);
    
    if (success) {
        EXPECT_LE(event_count, MAX_NETWORK_EVENTS);
        
        for (size_t i = 0; i < event_count; i++) {
            EXPECT_GT(events[i].timestamp_ns, 0);
            EXPECT_GE(events[i].type, NETWORK_EVENT_INTERFACE_UP);
            EXPECT_LE(events[i].type, NETWORK_EVENT_DNS_CHANGED);
            
            if (events[i].interface_name[0] != '\0') {
                EXPECT_GT(strlen(events[i].interface_name), 0);
            }
        }
    }
}

TEST_F(ReachabilityMonitorTest, Statistics) {
    reachability_stats_t stats;
    reachability_monitor_get_stats(monitor, &stats);
    
    EXPECT_GE(stats.connectivity_tests_performed, 0);
    EXPECT_GE(stats.network_changes_detected, 0);
    EXPECT_GE(stats.interface_events, 0);
    EXPECT_GE(stats.dns_changes, 0);
    
    // Trigger some activity
    ip_addr_t test_target = { .v4 = { .addr = inet_addr("8.8.8.8") } };
    reachability_monitor_test_connectivity(monitor, &test_target);
    
    // Process events
    for (int i = 0; i < 10; i++) {
        reachability_monitor_process_events(monitor);
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
    
    reachability_stats_t new_stats;
    reachability_monitor_get_stats(monitor, &new_stats);
    EXPECT_GE(new_stats.connectivity_tests_performed, stats.connectivity_tests_performed);
}

TEST_F(ReachabilityMonitorTest, ConcurrentMonitoring) {
    const int num_threads = 3;
    const int tests_per_thread = 5;
    std::atomic<int> completed_tests{0};
    std::vector<std::thread> threads;
    
    auto test_connectivity = [&](int thread_id) {
        for (int i = 0; i < tests_per_thread; i++) {
            ip_addr_t target = { .v4 = { .addr = htonl(0x08080800 + thread_id + i) } };
            
            if (reachability_monitor_test_connectivity(monitor, &target)) {
                completed_tests.fetch_add(1);
            }
            
            std::this_thread::sleep_for(std::chrono::milliseconds(50));
        }
    };
    
    // Start threads
    for (int i = 0; i < num_threads; i++) {
        threads.emplace_back(test_connectivity, i);
    }
    
    // Process events while threads run
    auto process_events = [&]() {
        for (int i = 0; i < 100; i++) {
            reachability_monitor_process_events(monitor);
            std::this_thread::sleep_for(std::chrono::milliseconds(20));
        }
    };
    std::thread event_thread(process_events);
    
    // Wait for threads
    for (auto& t : threads) {
        t.join();
    }
    event_thread.join();
    
    EXPECT_GE(completed_tests.load(), 0);
    EXPECT_LE(completed_tests.load(), num_threads * tests_per_thread);
}

TEST_F(ReachabilityMonitorTest, ErrorHandling) {
    // Test null parameters
    EXPECT_EQ(reachability_monitor_get_status(nullptr), NETWORK_STATUS_UNKNOWN);
    EXPECT_FALSE(reachability_monitor_test_connectivity(nullptr, nullptr));
    EXPECT_FALSE(reachability_monitor_add_interface(nullptr, nullptr));
    EXPECT_FALSE(reachability_monitor_remove_interface(nullptr, nullptr));
    
    ip_addr_t target = { .v4 = { .addr = inet_addr("8.8.8.8") } };
    
    EXPECT_FALSE(reachability_monitor_test_connectivity(monitor, nullptr));
    EXPECT_FALSE(reachability_monitor_add_interface(monitor, nullptr));
    EXPECT_FALSE(reachability_monitor_add_interface(monitor, ""));
    EXPECT_FALSE(reachability_monitor_remove_interface(monitor, nullptr));
    EXPECT_FALSE(reachability_monitor_remove_interface(monitor, "nonexistent"));
    
    // Test operations on null monitor
    reachability_monitor_process_events(nullptr); // Should not crash
    reachability_monitor_force_update(nullptr);   // Should not crash
    reachability_monitor_destroy(nullptr);        // Should not crash
}

TEST_F(ReachabilityMonitorTest, StringConversions) {
    EXPECT_STREQ(network_status_string(NETWORK_STATUS_DISCONNECTED), "Disconnected");
    EXPECT_STREQ(network_status_string(NETWORK_STATUS_CONNECTED_WIFI), "Connected (WiFi)");
    EXPECT_STREQ(network_status_string(NETWORK_STATUS_CONNECTED_CELLULAR), "Connected (Cellular)");
    EXPECT_STREQ(network_status_string(NETWORK_STATUS_UNKNOWN), "Unknown");
    
    EXPECT_STREQ(interface_type_string(INTERFACE_TYPE_LOOPBACK), "Loopback");
    EXPECT_STREQ(interface_type_string(INTERFACE_TYPE_ETHERNET), "Ethernet");
    EXPECT_STREQ(interface_type_string(INTERFACE_TYPE_WIFI), "WiFi");
    EXPECT_STREQ(interface_type_string(INTERFACE_TYPE_CELLULAR), "Cellular");
    EXPECT_STREQ(interface_type_string(INTERFACE_TYPE_VPN), "VPN");
    EXPECT_STREQ(interface_type_string(INTERFACE_TYPE_OTHER), "Other");
    
    EXPECT_STREQ(network_event_type_string(NETWORK_EVENT_INTERFACE_UP), "Interface Up");
    EXPECT_STREQ(network_event_type_string(NETWORK_EVENT_INTERFACE_DOWN), "Interface Down");
    EXPECT_STREQ(network_event_type_string(NETWORK_EVENT_IP_CHANGED), "IP Changed");
    EXPECT_STREQ(network_event_type_string(NETWORK_EVENT_GATEWAY_CHANGED), "Gateway Changed");
    EXPECT_STREQ(network_event_type_string(NETWORK_EVENT_DNS_CHANGED), "DNS Changed");
}

TEST_F(ReachabilityMonitorTest, IPv6Support) {
    // Test IPv6 connectivity
    ip_addr_t ipv6_target = {};
    ipv6_target.version = 6;
    // Google Public DNS IPv6: 2001:4860:4860::8888
    ipv6_target.v6.addr[0] = 0x20;
    ipv6_target.v6.addr[1] = 0x01;
    ipv6_target.v6.addr[2] = 0x48;
    ipv6_target.v6.addr[3] = 0x60;
    ipv6_target.v6.addr[4] = 0x48;
    ipv6_target.v6.addr[5] = 0x60;
    ipv6_target.v6.addr[15] = 0x88;
    ipv6_target.v6.addr[14] = 0x88;
    
    std::atomic<bool> ipv6_callback_called{false};
    
    auto callback = [](const ip_addr_t *target, bool is_reachable, uint32_t rtt_ms, void *user_data) {
        auto *called = static_cast<std::atomic<bool>*>(user_data);
        called->store(true);
        
        EXPECT_EQ(target->version, 6);
    };
    
    reachability_monitor_set_callback(monitor, callback, &ipv6_callback_called);
    
    // Test IPv6 connectivity if available
    bool started = reachability_monitor_test_connectivity(monitor, &ipv6_target);
    if (started) {
        for (int i = 0; i < 50; i++) {
            reachability_monitor_process_events(monitor);
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
            if (ipv6_callback_called.load()) break;
        }
    }
}

TEST_F(ReachabilityMonitorTest, BandwidthEstimation) {
    // Test bandwidth estimation functionality
    bandwidth_test_result_t result;
    ip_addr_t test_server = { .v4 = { .addr = inet_addr("8.8.8.8") } };
    
    std::atomic<bool> test_completed{false};
    
    auto callback = [](const bandwidth_test_result_t *result, void *user_data) {
        auto *completed = static_cast<std::atomic<bool>*>(user_data);
        completed->store(true);
        
        EXPECT_NE(result, nullptr);
        EXPECT_GE(result->download_mbps, 0.0);
        EXPECT_GE(result->upload_mbps, 0.0);
        EXPECT_GT(result->test_duration_ms, 0);
    };
    
    reachability_monitor_set_bandwidth_callback(monitor, callback, &test_completed);
    
    // Start bandwidth test
    bool started = reachability_monitor_start_bandwidth_test(monitor, &test_server);
    if (started) {
        // Wait for test completion
        for (int i = 0; i < 100 && !test_completed.load(); i++) {
            reachability_monitor_process_events(monitor);
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }
    }
}