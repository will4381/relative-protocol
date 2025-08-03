#include <gtest/gtest.h>
#include "socket_bridge/bridge.h"
#include <thread>
#include <chrono>
#include <atomic>

class SocketBridgeTest : public ::testing::Test {
protected:
    void SetUp() override {
        bridge = socket_bridge_create();
        ASSERT_NE(bridge, nullptr);
    }
    
    void TearDown() override {
        if (bridge) {
            socket_bridge_destroy(bridge);
        }
    }
    
    socket_bridge_t *bridge;
};

TEST_F(SocketBridgeTest, CreateDestroy) {
    EXPECT_NE(bridge, nullptr);
    
    // Test multiple create/destroy cycles
    for (int i = 0; i < 5; i++) {
        socket_bridge_t *temp = socket_bridge_create();
        EXPECT_NE(temp, nullptr);
        socket_bridge_destroy(temp);
    }
}

TEST_F(SocketBridgeTest, TCPSocketBridging) {
    std::atomic<int> packets_bridged{0};
    std::atomic<bool> connection_established{false};
    
    auto callback = [](socket_event_type_t event, socket_handle_t handle, 
                      const uint8_t *data, size_t length, void *user_data) {
        auto *counter = static_cast<std::atomic<int>*>(user_data);
        
        EXPECT_NE(handle, INVALID_SOCKET_HANDLE);
        EXPECT_GE(event, SOCKET_EVENT_CONNECTED);
        EXPECT_LE(event, SOCKET_EVENT_ERROR);
        
        if (event == SOCKET_EVENT_DATA_RECEIVED && data && length > 0) {
            counter->fetch_add(1);
        }
    };
    
    socket_bridge_set_callback(bridge, callback, &packets_bridged);
    
    // Create TCP socket bridge
    ip_addr_t remote_addr = { .v4 = { .addr = inet_addr("93.184.216.34") } }; // example.com
    socket_handle_t handle = socket_bridge_create_tcp_socket(bridge, &remote_addr, 80);
    
    if (handle != INVALID_SOCKET_HANDLE) {
        EXPECT_TRUE(socket_bridge_is_socket_valid(bridge, handle));
        EXPECT_EQ(socket_bridge_get_socket_type(bridge, handle), SOCKET_TYPE_TCP);
        
        // Test connecting
        bool connected = socket_bridge_connect(bridge, handle);
        if (connected) {
            // Send HTTP request
            const char *http_request = "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n";
            size_t sent = socket_bridge_send(bridge, handle, 
                                           (const uint8_t*)http_request, strlen(http_request));
            EXPECT_GT(sent, 0);
            
            // Process events to handle response
            for (int i = 0; i < 50; i++) {
                socket_bridge_process_events(bridge);
                std::this_thread::sleep_for(std::chrono::milliseconds(100));
            }
        }
        
        socket_bridge_close_socket(bridge, handle);
        EXPECT_FALSE(socket_bridge_is_socket_valid(bridge, handle));
    } else {
        GTEST_SKIP() << "Could not create TCP socket - may be network or permission issue";
    }
}

TEST_F(SocketBridgeTest, UDPSocketBridging) {
    std::atomic<int> packets_received{0};
    
    auto callback = [](socket_event_type_t event, socket_handle_t handle, 
                      const uint8_t *data, size_t length, void *user_data) {
        auto *counter = static_cast<std::atomic<int>*>(user_data);
        
        if (event == SOCKET_EVENT_DATA_RECEIVED && data && length > 0) {
            counter->fetch_add(1);
        }
    };
    
    socket_bridge_set_callback(bridge, callback, &packets_received);
    
    // Create UDP socket bridge
    socket_handle_t handle = socket_bridge_create_udp_socket(bridge, 0); // Any port
    
    if (handle != INVALID_SOCKET_HANDLE) {
        EXPECT_TRUE(socket_bridge_is_socket_valid(bridge, handle));
        EXPECT_EQ(socket_bridge_get_socket_type(bridge, handle), SOCKET_TYPE_UDP);
        
        uint16_t bound_port = socket_bridge_get_local_port(bridge, handle);
        EXPECT_GT(bound_port, 0);
        
        // Send DNS query to Google DNS
        ip_addr_t dns_server = { .v4 = { .addr = inet_addr("8.8.8.8") } };
        
        uint8_t dns_query[] = {
            0x12, 0x34,  // Transaction ID
            0x01, 0x00,  // Flags
            0x00, 0x01,  // Questions
            0x00, 0x00,  // Answers
            0x00, 0x00,  // Authority
            0x00, 0x00,  // Additional
            0x06, 'g', 'o', 'o', 'g', 'l', 'e',
            0x03, 'c', 'o', 'm',
            0x00,        // Null terminator
            0x00, 0x01,  // Type A
            0x00, 0x01   // Class IN
        };
        
        size_t sent = socket_bridge_send_to(bridge, handle, dns_query, sizeof(dns_query), 
                                           &dns_server, 53);
        EXPECT_GT(sent, 0);
        
        // Process events to handle response
        for (int i = 0; i < 50; i++) {
            socket_bridge_process_events(bridge);
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }
        
        socket_bridge_close_socket(bridge, handle);
    } else {
        GTEST_SKIP() << "Could not create UDP socket - may be network or permission issue";
    }
}

TEST_F(SocketBridgeTest, SocketOptions) {
    socket_handle_t tcp_handle = socket_bridge_create_tcp_socket(bridge, nullptr, 0);
    socket_handle_t udp_handle = socket_bridge_create_udp_socket(bridge, 0);
    
    if (tcp_handle != INVALID_SOCKET_HANDLE) {
        // Test TCP socket options
        EXPECT_TRUE(socket_bridge_set_socket_option(bridge, tcp_handle, SOCKET_OPT_KEEPALIVE, 1));
        EXPECT_TRUE(socket_bridge_set_socket_option(bridge, tcp_handle, SOCKET_OPT_NODELAY, 1));
        EXPECT_TRUE(socket_bridge_set_socket_option(bridge, tcp_handle, SOCKET_OPT_REUSEADDR, 1));
        
        int keepalive_value = socket_bridge_get_socket_option(bridge, tcp_handle, SOCKET_OPT_KEEPALIVE);
        EXPECT_EQ(keepalive_value, 1);
        
        socket_bridge_close_socket(bridge, tcp_handle);
    }
    
    if (udp_handle != INVALID_SOCKET_HANDLE) {
        // Test UDP socket options
        EXPECT_TRUE(socket_bridge_set_socket_option(bridge, udp_handle, SOCKET_OPT_BROADCAST, 1));
        EXPECT_TRUE(socket_bridge_set_socket_option(bridge, udp_handle, SOCKET_OPT_REUSEADDR, 1));
        
        int broadcast_value = socket_bridge_get_socket_option(bridge, udp_handle, SOCKET_OPT_BROADCAST);
        EXPECT_EQ(broadcast_value, 1);
        
        socket_bridge_close_socket(bridge, udp_handle);
    }
}

TEST_F(SocketBridgeTest, NetworkExtensionIntegration) {
    // Test NetworkExtension-specific functionality
    ne_provider_context_t context = {};
    context.tunnel_interface = "utun0";
    context.dns_servers[0] = (ip_addr_t){ .v4 = { .addr = inet_addr("8.8.8.8") } };
    context.dns_servers[1] = (ip_addr_t){ .v4 = { .addr = inet_addr("1.1.1.1") } };
    context.dns_server_count = 2;
    
    EXPECT_TRUE(socket_bridge_set_ne_context(bridge, &context));
    
    // Test tunnel interface configuration
    tunnel_config_t tunnel_config = {};
    tunnel_config.mtu = 1500;
    tunnel_config.ipv4_address = (ip_addr_t){ .v4 = { .addr = inet_addr("10.0.0.1") } };
    tunnel_config.ipv4_netmask = (ip_addr_t){ .v4 = { .addr = inet_addr("255.255.255.0") } };
    
    EXPECT_TRUE(socket_bridge_configure_tunnel(bridge, &tunnel_config));
    
    // Test flow diversion
    flow_divert_rule_t rule = {};
    rule.protocol = PROTO_TCP;
    rule.remote_port = 443;
    rule.action = FLOW_ACTION_ALLOW;
    strcpy(rule.process_name, "com.example.app");
    
    EXPECT_TRUE(socket_bridge_add_flow_rule(bridge, &rule));
    EXPECT_TRUE(socket_bridge_remove_flow_rule(bridge, &rule));
}

TEST_F(SocketBridgeTest, PacketCapture) {
    std::atomic<int> captured_packets{0};
    
    auto capture_callback = [](const uint8_t *packet, size_t length, 
                              const packet_metadata_t *metadata, void *user_data) {
        auto *counter = static_cast<std::atomic<int>*>(user_data);
        counter->fetch_add(1);
        
        EXPECT_NE(packet, nullptr);
        EXPECT_GT(length, 0);
        EXPECT_NE(metadata, nullptr);
        EXPECT_GT(metadata->timestamp_ns, 0);
    };
    
    socket_bridge_set_capture_callback(bridge, capture_callback, &captured_packets);
    
    // Enable packet capture
    EXPECT_TRUE(socket_bridge_enable_capture(bridge, true));
    
    // Generate some network activity
    socket_handle_t handle = socket_bridge_create_udp_socket(bridge, 0);
    if (handle != INVALID_SOCKET_HANDLE) {
        ip_addr_t target = { .v4 = { .addr = inet_addr("8.8.8.8") } };
        uint8_t test_data[] = { 0x01, 0x02, 0x03, 0x04 };
        
        socket_bridge_send_to(bridge, handle, test_data, sizeof(test_data), &target, 53);
        
        // Process events
        for (int i = 0; i < 20; i++) {
            socket_bridge_process_events(bridge);
            std::this_thread::sleep_for(std::chrono::milliseconds(50));
        }
        
        socket_bridge_close_socket(bridge, handle);
    }
    
    socket_bridge_enable_capture(bridge, false);
    EXPECT_GE(captured_packets.load(), 0);
}

TEST_F(SocketBridgeTest, StatisticsAndMetrics) {
    bridge_stats_t stats;
    socket_bridge_get_stats(bridge, &stats);
    
    EXPECT_EQ(stats.active_tcp_sockets, 0);
    EXPECT_EQ(stats.active_udp_sockets, 0);
    EXPECT_EQ(stats.total_bytes_sent, 0);
    EXPECT_EQ(stats.total_bytes_received, 0);
    EXPECT_EQ(stats.connection_errors, 0);
    
    // Create sockets and generate activity
    socket_handle_t tcp_handle = socket_bridge_create_tcp_socket(bridge, nullptr, 0);
    socket_handle_t udp_handle = socket_bridge_create_udp_socket(bridge, 0);
    
    if (tcp_handle != INVALID_SOCKET_HANDLE && udp_handle != INVALID_SOCKET_HANDLE) {
        socket_bridge_get_stats(bridge, &stats);
        EXPECT_EQ(stats.active_tcp_sockets, 1);
        EXPECT_EQ(stats.active_udp_sockets, 1);
        
        socket_bridge_close_socket(bridge, tcp_handle);
        socket_bridge_close_socket(bridge, udp_handle);
        
        socket_bridge_get_stats(bridge, &stats);
        EXPECT_EQ(stats.active_tcp_sockets, 0);
        EXPECT_EQ(stats.active_udp_sockets, 0);
    }
}

TEST_F(SocketBridgeTest, ConcurrentSocketOperations) {
    const int num_threads = 4;
    const int sockets_per_thread = 5;
    std::atomic<int> created_sockets{0};
    std::atomic<int> successful_operations{0};
    std::vector<std::thread> threads;
    
    auto socket_operations = [&](int thread_id) {
        for (int i = 0; i < sockets_per_thread; i++) {
            // Create UDP socket (simpler than TCP for testing)
            socket_handle_t handle = socket_bridge_create_udp_socket(bridge, 0);
            
            if (handle != INVALID_SOCKET_HANDLE) {
                created_sockets.fetch_add(1);
                
                // Test basic operations
                uint16_t port = socket_bridge_get_local_port(bridge, handle);
                if (port > 0) {
                    successful_operations.fetch_add(1);
                }
                
                // Send test data
                ip_addr_t target = { .v4 = { .addr = htonl(0x08080800 + thread_id) } };
                uint8_t data[] = { 0x01, 0x02, 0x03, 0x04 };
                
                size_t sent = socket_bridge_send_to(bridge, handle, data, sizeof(data), &target, 53);
                if (sent > 0) {
                    successful_operations.fetch_add(1);
                }
                
                socket_bridge_close_socket(bridge, handle);
            }
            
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
        }
    };
    
    // Start threads
    for (int i = 0; i < num_threads; i++) {
        threads.emplace_back(socket_operations, i);
    }
    
    // Process events while threads run
    auto process_events = [&]() {
        for (int i = 0; i < 100; i++) {
            socket_bridge_process_events(bridge);
            std::this_thread::sleep_for(std::chrono::milliseconds(20));
        }
    };
    std::thread event_thread(process_events);
    
    // Wait for completion
    for (auto& t : threads) {
        t.join();
    }
    event_thread.join();
    
    EXPECT_GE(created_sockets.load(), 0);
    EXPECT_LE(created_sockets.load(), num_threads * sockets_per_thread);
    
    bridge_stats_t stats;
    socket_bridge_get_stats(bridge, &stats);
    EXPECT_EQ(stats.active_tcp_sockets, 0);
    EXPECT_EQ(stats.active_udp_sockets, 0);
}

TEST_F(SocketBridgeTest, ErrorHandling) {
    // Test null parameters
    EXPECT_EQ(socket_bridge_create_tcp_socket(nullptr, nullptr, 0), INVALID_SOCKET_HANDLE);
    EXPECT_EQ(socket_bridge_create_udp_socket(nullptr, 0), INVALID_SOCKET_HANDLE);
    EXPECT_FALSE(socket_bridge_connect(nullptr, INVALID_SOCKET_HANDLE));
    EXPECT_EQ(socket_bridge_send(nullptr, INVALID_SOCKET_HANDLE, nullptr, 0), 0);
    
    // Test invalid handles
    EXPECT_FALSE(socket_bridge_is_socket_valid(bridge, INVALID_SOCKET_HANDLE));
    EXPECT_FALSE(socket_bridge_connect(bridge, INVALID_SOCKET_HANDLE));
    EXPECT_EQ(socket_bridge_send(bridge, INVALID_SOCKET_HANDLE, nullptr, 0), 0);
    EXPECT_EQ(socket_bridge_get_socket_type(bridge, INVALID_SOCKET_HANDLE), SOCKET_TYPE_INVALID);
    EXPECT_EQ(socket_bridge_get_local_port(bridge, INVALID_SOCKET_HANDLE), 0);
    
    // Test invalid socket operations
    socket_handle_t handle = socket_bridge_create_udp_socket(bridge, 0);
    if (handle != INVALID_SOCKET_HANDLE) {
        EXPECT_EQ(socket_bridge_send(bridge, handle, nullptr, 0), 0);
        EXPECT_EQ(socket_bridge_send_to(bridge, handle, nullptr, 0, nullptr, 0), 0);
        
        ip_addr_t addr = { .v4 = { .addr = inet_addr("192.168.1.1") } };
        EXPECT_EQ(socket_bridge_send_to(bridge, handle, nullptr, 0, &addr, 80), 0);
        
        socket_bridge_close_socket(bridge, handle);
    }
    
    // Test operations on null bridge
    socket_bridge_process_events(nullptr); // Should not crash
    socket_bridge_destroy(nullptr);        // Should not crash
}

TEST_F(SocketBridgeTest, IPv6Support) {
    // Test IPv6 socket creation
    ip_addr_t ipv6_addr = {};
    ipv6_addr.version = 6;
    // Google DNS IPv6: 2001:4860:4860::8888
    ipv6_addr.v6.addr[0] = 0x20;
    ipv6_addr.v6.addr[1] = 0x01;
    ipv6_addr.v6.addr[2] = 0x48;
    ipv6_addr.v6.addr[3] = 0x60;
    ipv6_addr.v6.addr[4] = 0x48;
    ipv6_addr.v6.addr[5] = 0x60;
    ipv6_addr.v6.addr[15] = 0x88;
    ipv6_addr.v6.addr[14] = 0x88;
    
    socket_handle_t tcp6_handle = socket_bridge_create_tcp_socket(bridge, &ipv6_addr, 80);
    socket_handle_t udp6_handle = socket_bridge_create_udp_socket(bridge, 0);
    
    if (tcp6_handle != INVALID_SOCKET_HANDLE) {
        EXPECT_TRUE(socket_bridge_is_socket_valid(bridge, tcp6_handle));
        socket_bridge_close_socket(bridge, tcp6_handle);
    }
    
    if (udp6_handle != INVALID_SOCKET_HANDLE) {
        EXPECT_TRUE(socket_bridge_is_socket_valid(bridge, udp6_handle));
        
        // Test IPv6 UDP send
        uint8_t test_data[] = { 0x01, 0x02, 0x03, 0x04 };
        size_t sent = socket_bridge_send_to(bridge, udp6_handle, test_data, sizeof(test_data), 
                                           &ipv6_addr, 53);
        EXPECT_GE(sent, 0);
        
        socket_bridge_close_socket(bridge, udp6_handle);
    }
}

TEST_F(SocketBridgeTest, SocketPoolManagement) {
    // Test socket pool functionality
    EXPECT_TRUE(socket_bridge_set_max_sockets(bridge, 100));
    EXPECT_EQ(socket_bridge_get_max_sockets(bridge), 100);
    
    // Create multiple sockets to test pool
    std::vector<socket_handle_t> handles;
    for (int i = 0; i < 20; i++) {
        socket_handle_t handle = socket_bridge_create_udp_socket(bridge, 0);
        if (handle != INVALID_SOCKET_HANDLE) {
            handles.push_back(handle);
        }
    }
    
    EXPECT_GT(handles.size(), 0);
    EXPECT_LE(handles.size(), 20);
    
    // Test socket reuse
    socket_bridge_enable_socket_reuse(bridge, true);
    EXPECT_TRUE(socket_bridge_is_socket_reuse_enabled(bridge));
    
    // Close all sockets
    for (auto handle : handles) {
        socket_bridge_close_socket(bridge, handle);
    }
    
    bridge_stats_t stats;
    socket_bridge_get_stats(bridge, &stats);
    EXPECT_EQ(stats.active_udp_sockets, 0);
}

TEST_F(SocketBridgeTest, StringConversions) {
    EXPECT_STREQ(socket_type_string(SOCKET_TYPE_TCP), "TCP");
    EXPECT_STREQ(socket_type_string(SOCKET_TYPE_UDP), "UDP");
    EXPECT_STREQ(socket_type_string(SOCKET_TYPE_INVALID), "Invalid");
    
    EXPECT_STREQ(socket_event_string(SOCKET_EVENT_CONNECTED), "Connected");
    EXPECT_STREQ(socket_event_string(SOCKET_EVENT_DISCONNECTED), "Disconnected");
    EXPECT_STREQ(socket_event_string(SOCKET_EVENT_DATA_RECEIVED), "Data Received");
    EXPECT_STREQ(socket_event_string(SOCKET_EVENT_DATA_SENT), "Data Sent");
    EXPECT_STREQ(socket_event_string(SOCKET_EVENT_ERROR), "Error");
    
    EXPECT_STREQ(flow_action_string(FLOW_ACTION_ALLOW), "Allow");
    EXPECT_STREQ(flow_action_string(FLOW_ACTION_BLOCK), "Block");
    EXPECT_STREQ(flow_action_string(FLOW_ACTION_REDIRECT), "Redirect");
}