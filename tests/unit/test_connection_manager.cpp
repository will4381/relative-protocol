#include <gtest/gtest.h>
#include "tcp_udp/connection_manager.h"
#include "api/relative_vpn.h"  // For vpn_metrics_t definition
#include <thread>
#include <chrono>
#include <atomic>
#include <arpa/inet.h>  // For inet_addr

class ConnectionManagerTest : public ::testing::Test {
protected:
    void SetUp() override {
        manager = connection_manager_create();
        ASSERT_NE(manager, nullptr);
    }
    
    void TearDown() override {
        if (manager) {
            connection_manager_destroy(manager);
        }
    }
    
    connection_manager_t *manager;
};

TEST_F(ConnectionManagerTest, CreateDestroy) {
    EXPECT_NE(manager, nullptr);
    EXPECT_EQ(connection_manager_get_tcp_count(manager), 0);
    EXPECT_EQ(connection_manager_get_udp_count(manager), 0);
}

TEST_F(ConnectionManagerTest, TCPConnectionLifecycle) {
    std::atomic<int> callback_count{0};
    std::atomic<connection_event_t> last_event{CONN_EVENT_CLOSED};
    
    auto callback = [](tcp_connection_t *conn, connection_event_t event, void *data, size_t length, void *user_data) {
        auto *count = static_cast<std::atomic<int>*>(user_data);
        count->fetch_add(1);
        
        EXPECT_NE(conn, nullptr);
        EXPECT_GE(event, CONN_EVENT_ESTABLISHED);
        EXPECT_LE(event, CONN_EVENT_ERROR);
    };
    
    ip_addr_t remote_addr = { .v4 = { .addr = inet_addr("93.184.216.34") } }; // example.com
    
    tcp_connection_t *conn = tcp_connection_create(manager, &remote_addr, 80, callback, &callback_count);
    EXPECT_NE(conn, nullptr);
    
    if (conn) {
        EXPECT_EQ(connection_manager_get_tcp_count(manager), 1);
        EXPECT_EQ(tcp_connection_get_state(conn), CONN_SYN_SENT);
        EXPECT_GT(tcp_connection_get_seq(conn), 0);
        
        // Test sending data
        const char *test_data = "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n";
        EXPECT_TRUE(tcp_connection_send(conn, (const uint8_t*)test_data, strlen(test_data)));
        
        // Test closing
        EXPECT_TRUE(tcp_connection_close(conn));
        
        tcp_connection_destroy(conn);
        EXPECT_EQ(connection_manager_get_tcp_count(manager), 0);
    }
}

TEST_F(ConnectionManagerTest, UDPSessionLifecycle) {
    std::atomic<int> callback_count{0};
    
    auto callback = [](udp_session_t *session, const uint8_t *data, size_t length, 
                      const ip_addr_t *src_addr, uint16_t src_port, void *user_data) {
        auto *count = static_cast<std::atomic<int>*>(user_data);
        count->fetch_add(1);
        
        EXPECT_NE(session, nullptr);
        EXPECT_NE(data, nullptr);
        EXPECT_GT(length, 0);
    };
    
    udp_session_t *session = udp_session_create(manager, 0, callback, &callback_count);
    EXPECT_NE(session, nullptr);
    
    if (session) {
        EXPECT_EQ(connection_manager_get_udp_count(manager), 1);
        EXPECT_GT(udp_session_get_port(session), 0);
        
        // Test sending data
        ip_addr_t dest_addr = { .v4 = { .addr = inet_addr("8.8.8.8") } };
        const char *test_data = "test UDP data";
        EXPECT_TRUE(udp_session_send(session, (const uint8_t*)test_data, strlen(test_data), &dest_addr, 53));
        
        udp_session_destroy(session);
        EXPECT_EQ(connection_manager_get_udp_count(manager), 0);
    }
}

TEST_F(ConnectionManagerTest, PacketProcessing) {
    // Create a mock TCP packet
    uint8_t tcp_packet[] = {
        // IPv4 header
        0x45, 0x00, 0x00, 0x28,  // Version, IHL, ToS, Length
        0x00, 0x01, 0x40, 0x00,  // ID, Flags, Fragment
        0x40, 0x06, 0x00, 0x00,  // TTL, Protocol (TCP), Checksum
        0x7f, 0x00, 0x00, 0x01,  // Source IP
        0x7f, 0x00, 0x00, 0x01,  // Dest IP
        // TCP header
        0x00, 0x50, 0x1f, 0x90,  // Source port, Dest port
        0x00, 0x00, 0x00, 0x01,  // Seq number
        0x00, 0x00, 0x00, 0x00,  // Ack number
        0x50, 0x02, 0x20, 0x00,  // Header len, Flags, Window
        0x00, 0x00, 0x00, 0x00   // Checksum, Urgent
    };
    
    packet_info_t packet = {};
    packet.data = tcp_packet;
    packet.length = sizeof(tcp_packet);
    packet.flow.ip_version = 4;
    packet.flow.protocol = PROTO_TCP;
    packet.flow.src_ip.v4.addr = inet_addr("127.0.0.1");
    packet.flow.dst_ip.v4.addr = inet_addr("127.0.0.1");
    packet.flow.src_port = 80;
    packet.flow.dst_port = 8080;
    packet.timestamp_ns = clock_gettime_nsec_np(CLOCK_MONOTONIC);
    
    // This should not crash even without matching connections
    connection_manager_process_packet(manager, &packet);
    
    // Process events
    EXPECT_TRUE(connection_manager_process_events(manager));
}

TEST_F(ConnectionManagerTest, Statistics) {
    vpn_metrics_t metrics = {};
    connection_manager_get_stats(manager, &metrics);
    
    // Initially should be zero
    EXPECT_EQ(metrics.tcp_connections, 0);
    EXPECT_EQ(metrics.udp_sessions, 0);
    
    // Create connections and check stats
    ip_addr_t addr = { .v4 = { .addr = inet_addr("192.168.1.1") } };
    tcp_connection_t *tcp_conn = tcp_connection_create(manager, &addr, 80, nullptr, nullptr);
    udp_session_t *udp_session = udp_session_create(manager, 0, nullptr, nullptr);
    
    if (tcp_conn && udp_session) {
        connection_manager_get_stats(manager, &metrics);
        EXPECT_EQ(metrics.tcp_connections, 1);
        EXPECT_EQ(metrics.udp_sessions, 1);
        
        tcp_connection_destroy(tcp_conn);
        udp_session_destroy(udp_session);
    }
}

TEST_F(ConnectionManagerTest, ConcurrentConnections) {
    const int num_threads = 4;
    const int connections_per_thread = 5;
    std::atomic<int> created_count{0};
    std::vector<std::thread> threads;
    
    auto create_connections = [&](int thread_id) {
        for (int i = 0; i < connections_per_thread; i++) {
            ip_addr_t addr = { .v4 = { .addr = htonl(0xC0A80100 + thread_id * 10 + i) } };
            
            tcp_connection_t *tcp_conn = tcp_connection_create(manager, &addr, 80 + i, nullptr, nullptr);
            udp_session_t *udp_session = udp_session_create(manager, 0, nullptr, nullptr);
            
            if (tcp_conn && udp_session) {
                created_count.fetch_add(2);
                
                // Brief delay to allow other threads to interleave
                std::this_thread::sleep_for(std::chrono::milliseconds(1));
                
                tcp_connection_destroy(tcp_conn);
                udp_session_destroy(udp_session);
            }
        }
    };
    
    // Start threads
    for (int i = 0; i < num_threads; i++) {
        threads.emplace_back(create_connections, i);
    }
    
    // Wait for completion
    for (auto& t : threads) {
        t.join();
    }
    
    // All connections should be created and destroyed
    EXPECT_EQ(created_count.load(), num_threads * connections_per_thread * 2);
    EXPECT_EQ(connection_manager_get_tcp_count(manager), 0);
    EXPECT_EQ(connection_manager_get_udp_count(manager), 0);
}

TEST_F(ConnectionManagerTest, ErrorHandling) {
    // Test null parameters
    EXPECT_EQ(tcp_connection_create(nullptr, nullptr, 0, nullptr, nullptr), nullptr);
    EXPECT_EQ(udp_session_create(nullptr, 0, nullptr, nullptr), nullptr);
    
    ip_addr_t addr = { .v4 = { .addr = inet_addr("192.168.1.1") } };
    
    EXPECT_EQ(tcp_connection_create(manager, nullptr, 80, nullptr, nullptr), nullptr);
    EXPECT_EQ(tcp_connection_create(manager, &addr, 80, nullptr, nullptr), nullptr); // No callback
    
    EXPECT_EQ(udp_session_create(manager, 0, nullptr, nullptr), nullptr); // No callback
    
    // Test operations on null connections
    EXPECT_FALSE(tcp_connection_send(nullptr, nullptr, 0));
    EXPECT_FALSE(tcp_connection_close(nullptr));
    EXPECT_EQ(tcp_connection_get_state(nullptr), CONN_CLOSED);
    EXPECT_EQ(tcp_connection_get_seq(nullptr), 0);
    EXPECT_EQ(tcp_connection_get_ack(nullptr), 0);
    
    EXPECT_FALSE(udp_session_send(nullptr, nullptr, 0, nullptr, 0));
    EXPECT_EQ(udp_session_get_port(nullptr), 0);
    
    tcp_connection_destroy(nullptr); // Should not crash
    udp_session_destroy(nullptr);    // Should not crash
    
    connection_manager_process_packet(manager, nullptr); // Should not crash
    connection_manager_process_packet(nullptr, nullptr); // Should not crash
}

TEST_F(ConnectionManagerTest, MemoryStress) {
    const int max_connections = 100;
    std::vector<tcp_connection_t*> tcp_connections;
    std::vector<udp_session_t*> udp_sessions;
    
    // Create many connections
    for (int i = 0; i < max_connections; i++) {
        ip_addr_t addr = { .v4 = { .addr = htonl(0xC0A80100 + i) } };
        
        auto tcp_callback = [](tcp_connection_t *conn, connection_event_t event, void *data, size_t length, void *user_data) {
            // Minimal callback
        };
        
        auto udp_callback = [](udp_session_t *session, const uint8_t *data, size_t length, 
                              const ip_addr_t *src_addr, uint16_t src_port, void *user_data) {
            // Minimal callback  
        };
        
        tcp_connection_t *tcp_conn = tcp_connection_create(manager, &addr, 80 + i, tcp_callback, nullptr);
        udp_session_t *udp_session = udp_session_create(manager, 0, udp_callback, nullptr);
        
        if (tcp_conn) tcp_connections.push_back(tcp_conn);
        if (udp_session) udp_sessions.push_back(udp_session);
    }
    
    EXPECT_GT(tcp_connections.size(), 0);
    EXPECT_GT(udp_sessions.size(), 0);
    
    // Process events multiple times
    for (int i = 0; i < 10; i++) {
        connection_manager_process_events(manager);
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
    
    // Clean up all connections
    for (auto conn : tcp_connections) {
        tcp_connection_destroy(conn);
    }
    for (auto session : udp_sessions) {
        udp_session_destroy(session);
    }
    
    EXPECT_EQ(connection_manager_get_tcp_count(manager), 0);
    EXPECT_EQ(connection_manager_get_udp_count(manager), 0);
}