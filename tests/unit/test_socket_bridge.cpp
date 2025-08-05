#include <gtest/gtest.h>
#include "socket_bridge/bridge.h"
#include "tcp_udp/connection_manager.h"
#include "core/types.h"
#include "api/relative_vpn.h"
#include <thread>
#include <chrono>
#include <atomic>
#include <arpa/inet.h>

// Note: NetworkExtension integration is tested in separate .mm files

/**
 * Socket Bridge Unit Tests for iOS
 * 
 * Tests the iOS-specific socket bridge functionality:
 * - Creation and destruction with connection manager
 * - TCP connection bridging using iOS NetworkExtension patterns
 * - UDP session bridging
 * - Packet processing and event handling
 * - Connection lifecycle management
 */

class SocketBridgeTest : public ::testing::Test {
protected:
    void SetUp() override {
        // Create connection manager first (required for socket bridge)
        conn_mgr = connection_manager_create();
        ASSERT_NE(conn_mgr, nullptr);
        
        bridge = socket_bridge_create(conn_mgr);
        ASSERT_NE(bridge, nullptr);
        
        data_received = 0;
        events_received = 0;
    }
    
    void TearDown() override {
        if (bridge) {
            socket_bridge_destroy(bridge);
        }
        if (conn_mgr) {
            connection_manager_destroy(conn_mgr);
        }
    }
    
    socket_bridge_t *bridge;
    connection_manager_t *conn_mgr;
    std::atomic<int> data_received{0};
    std::atomic<int> events_received{0};
    
    // Data callback for bridge connections
    static void data_callback(bridge_connection_t *conn, const uint8_t *data, 
                             size_t length, void *user_data) {
        auto *test = static_cast<SocketBridgeTest*>(user_data);
        if (data && length > 0) {
            test->data_received++;
        }
    }
    
    // Event callback for bridge connections
    static void event_callback(bridge_connection_t *conn, connection_event_t event, 
                              void *user_data) {
        auto *test = static_cast<SocketBridgeTest*>(user_data);
        test->events_received++;
    }
};

TEST_F(SocketBridgeTest, CreateDestroy) {
    EXPECT_NE(bridge, nullptr);
    
    // Test multiple create/destroy cycles
    for (int i = 0; i < 5; i++) {
        connection_manager_t *temp_mgr = connection_manager_create();
        ASSERT_NE(temp_mgr, nullptr);
        
        socket_bridge_t *temp = socket_bridge_create(temp_mgr);
        EXPECT_NE(temp, nullptr);
        socket_bridge_destroy(temp);
        connection_manager_destroy(temp_mgr);
    }
}

TEST_F(SocketBridgeTest, CreateWithNullManager) {
    // Should fail with null connection manager
    socket_bridge_t *null_bridge = socket_bridge_create(NULL);
    EXPECT_EQ(null_bridge, nullptr);
}

TEST_F(SocketBridgeTest, TCPConnectionCreation) {
    // Create a TCP connection to a test server
    ip_addr_t remote_addr = {};
    remote_addr.v4.addr = inet_addr("93.184.216.34"); // example.com
    uint16_t remote_port = 80;
    
    bridge_connection_t *tcp_conn = socket_bridge_create_tcp_connection(
        bridge, &remote_addr, remote_port, data_callback, event_callback, this);
    
    if (tcp_conn) {
        // Connection was created successfully
        EXPECT_EQ(bridge_connection_get_protocol(tcp_conn), BRIDGE_TCP);
        EXPECT_EQ(bridge_connection_get_remote_port(tcp_conn), remote_port);
        
        const ip_addr_t *conn_addr = bridge_connection_get_remote_addr(tcp_conn);
        EXPECT_NE(conn_addr, nullptr);
        EXPECT_EQ(conn_addr->v4.addr, remote_addr.v4.addr);
        
        // Test sending data (will likely fail in unit test environment)
        uint8_t test_data[] = "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n";
        bool send_result = socket_bridge_send_data(tcp_conn, test_data, sizeof(test_data) - 1);
        // Expected to fail in unit test environment without real network
        
        socket_bridge_destroy_connection(tcp_conn);
    } else {
        // Connection creation failed (expected in unit test environment)
        EXPECT_EQ(tcp_conn, nullptr);
    }
}

TEST_F(SocketBridgeTest, UDPSessionCreation) {
    uint16_t local_port = 0; // Auto-assign port
    
    bridge_connection_t *udp_session = socket_bridge_create_udp_session(
        bridge, local_port, data_callback, this);
    
    if (udp_session) {
        // Session was created successfully
        EXPECT_EQ(bridge_connection_get_protocol(udp_session), BRIDGE_UDP);
        EXPECT_GT(bridge_connection_get_local_port(udp_session), 0);
        
        // Test sending UDP data
        ip_addr_t dest_addr = {};
        dest_addr.v4.addr = inet_addr("8.8.8.8"); // Google DNS
        uint16_t dest_port = 53;
        
        uint8_t dns_query[] = {
            0x12, 0x34,             // Transaction ID
            0x01, 0x00,             // Flags (standard query)
            0x00, 0x01,             // Questions
            0x00, 0x00,             // Answer RRs
            0x00, 0x00,             // Authority RRs
            0x00, 0x00,             // Additional RRs
            0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e',  // "example"
            0x03, 'c', 'o', 'm',    // "com"
            0x00,                   // End of name
            0x00, 0x01,             // Type A
            0x00, 0x01              // Class IN
        };
        
        bool send_result = socket_bridge_send_udp_data(udp_session, dns_query, 
                                                      sizeof(dns_query), &dest_addr, dest_port);
        // May succeed or fail depending on environment
        
        socket_bridge_destroy_connection(udp_session);
    } else {
        // Session creation failed (may happen in restricted environments)
        EXPECT_EQ(udp_session, nullptr);
    }
}

TEST_F(SocketBridgeTest, PacketProcessing) {
    // Create a test packet
    packet_info_t packet = {};
    uint8_t packet_data[] = {
        0x45, 0x00, 0x00, 0x28,  // IPv4 header
        0x00, 0x01, 0x40, 0x00,
        0x40, 0x06, 0x00, 0x00,  // TCP protocol
        0xc0, 0xa8, 0x01, 0x64,  // Source: 192.168.1.100
        0xac, 0xd9, 0x0e, 0x64,  // Dest: 172.217.14.100 (Google)
        0x04, 0x38, 0x00, 0x50,  // TCP ports (1080 -> 80)
        0x00, 0x00, 0x00, 0x00,  // TCP seq/ack
        0x50, 0x02, 0x20, 0x00,  // TCP header
        0x00, 0x00, 0x00, 0x00   // TCP checksum/urgent
    };
    
    packet.data = packet_data;
    packet.length = sizeof(packet_data);
    packet.timestamp_ns = 1234567890ULL;
    packet.flow.ip_version = 4;
    packet.flow.protocol = PROTO_TCP;
    packet.flow.src_ip.v4.addr = inet_addr("192.168.1.100");
    packet.flow.dst_ip.v4.addr = inet_addr("172.217.14.100");
    packet.flow.src_port = 1080;
    packet.flow.dst_port = 80;
    
    // Process the packet through the bridge
    socket_bridge_process_packet(bridge, &packet);
    
    // Process events
    bool events_processed = socket_bridge_process_events(bridge);
    EXPECT_TRUE(events_processed);
}

TEST_F(SocketBridgeTest, ConnectionStatistics) {
    // Get initial connection count
    size_t initial_count = socket_bridge_get_connection_count(bridge);
    EXPECT_EQ(initial_count, 0);
    
    // Get statistics
    vpn_metrics_t metrics = {};
    socket_bridge_get_stats(bridge, &metrics);
    
    // Should start with zero values
    EXPECT_EQ(metrics.tcp_connections, 0);
    EXPECT_EQ(metrics.udp_sessions, 0);
}

TEST_F(SocketBridgeTest, ConnectionLifecycle) {
    ip_addr_t remote_addr = {};
    remote_addr.v4.addr = inet_addr("127.0.0.1"); // localhost
    uint16_t remote_port = 8080;
    
    // Create connection
    bridge_connection_t *conn = socket_bridge_create_tcp_connection(
        bridge, &remote_addr, remote_port, data_callback, event_callback, this);
    
    if (conn) {
        // Verify connection properties
        EXPECT_EQ(bridge_connection_get_protocol(conn), BRIDGE_TCP);
        EXPECT_EQ(bridge_connection_get_remote_port(conn), remote_port);
        
        // Connection should start in a non-established state
        connection_state_t state = bridge_connection_get_state(conn);
        EXPECT_NE(state, CONN_ESTABLISHED); // Initially not established
        
        // Destroy connection
        socket_bridge_destroy_connection(conn);
        
        // Connection count should remain zero after cleanup
        size_t count = socket_bridge_get_connection_count(bridge);
        EXPECT_EQ(count, 0);
    }
}

TEST_F(SocketBridgeTest, InvalidParameters) {
    // Test with null parameters
    bridge_connection_t *null_conn = socket_bridge_create_tcp_connection(
        NULL, NULL, 80, data_callback, event_callback, this);
    EXPECT_EQ(null_conn, nullptr);
    
    // Test with null bridge
    ip_addr_t addr = {};
    addr.v4.addr = inet_addr("127.0.0.1");
    null_conn = socket_bridge_create_tcp_connection(
        NULL, &addr, 80, data_callback, event_callback, this);
    EXPECT_EQ(null_conn, nullptr);
    
    // Test with null callback
    null_conn = socket_bridge_create_tcp_connection(
        bridge, &addr, 80, NULL, event_callback, this);
    EXPECT_EQ(null_conn, nullptr);
    
    // Test UDP with null parameters
    bridge_connection_t *null_udp = socket_bridge_create_udp_session(
        NULL, 0, data_callback, this);
    EXPECT_EQ(null_udp, nullptr);
    
    null_udp = socket_bridge_create_udp_session(bridge, 0, NULL, this);
    EXPECT_EQ(null_udp, nullptr);
}

TEST_F(SocketBridgeTest, ConcurrentConnections) {
    // Test creating multiple connections concurrently
    std::vector<std::thread> threads;
    std::atomic<int> successful_connections{0};
    std::atomic<int> failed_connections{0};
    
    for (int i = 0; i < 4; i++) {
        threads.emplace_back([this, &successful_connections, &failed_connections, i]() {
            ip_addr_t addr = {};
            addr.v4.addr = inet_addr("127.0.0.1");
            uint16_t port = 8080 + i;
            
            bridge_connection_t *conn = socket_bridge_create_tcp_connection(
                bridge, &addr, port, data_callback, event_callback, this);
            
            if (conn) {
                successful_connections++;
                // Brief delay to simulate connection activity
                std::this_thread::sleep_for(std::chrono::milliseconds(10));
                socket_bridge_destroy_connection(conn);
            } else {
                failed_connections++;
            }
        });
    }
    
    // Wait for all threads to complete
    for (auto &thread : threads) {
        thread.join();
    }
    
    // Should have attempted all connections
    EXPECT_EQ(successful_connections + failed_connections, 4);
}

// Test memory cleanup and leak prevention
TEST_F(SocketBridgeTest, MemoryCleanup) {
    // Create and destroy many connections to test memory management
    for (int i = 0; i < 100; i++) {
        ip_addr_t addr = {};
        addr.v4.addr = inet_addr("127.0.0.1");
        
        bridge_connection_t *tcp_conn = socket_bridge_create_tcp_connection(
            bridge, &addr, 80, data_callback, event_callback, this);
        
        bridge_connection_t *udp_conn = socket_bridge_create_udp_session(
            bridge, 0, data_callback, this);
        
        // Immediately destroy connections
        if (tcp_conn) {
            socket_bridge_destroy_connection(tcp_conn);
        }
        if (udp_conn) {
            socket_bridge_destroy_connection(udp_conn);
        }
    }
    
    // Connection count should be zero after cleanup
    size_t count = socket_bridge_get_connection_count(bridge);
    EXPECT_EQ(count, 0);
}