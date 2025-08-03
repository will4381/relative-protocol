#include <gtest/gtest.h>
#include "classifier/tls_quic.h"
#include <thread>
#include <chrono>
#include <atomic>

class TrafficClassifierTest : public ::testing::Test {
protected:
    void SetUp() override {
        classifier = traffic_classifier_create();
        ASSERT_NE(classifier, nullptr);
    }
    
    void TearDown() override {
        if (classifier) {
            traffic_classifier_destroy(classifier);
        }
    }
    
    traffic_classifier_t *classifier;
};

TEST_F(TrafficClassifierTest, CreateDestroy) {
    EXPECT_NE(classifier, nullptr);
    
    // Test multiple create/destroy cycles
    for (int i = 0; i < 5; i++) {
        traffic_classifier_t *temp = traffic_classifier_create();
        EXPECT_NE(temp, nullptr);
        traffic_classifier_destroy(temp);
    }
}

TEST_F(TrafficClassifierTest, TLSDetection) {
    // TLS 1.3 Client Hello packet
    uint8_t tls13_hello[] = {
        0x16, 0x03, 0x01, 0x00, 0xc4,  // TLS Record Header (Handshake, TLS 1.0, Length 196)
        0x01, 0x00, 0x00, 0xc0,        // Handshake Header (Client Hello, Length 192)
        0x03, 0x04,                    // TLS Version 1.3
        // Random (32 bytes)
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
        0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
        0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20,
        0x00,                          // Session ID length (0)
        0x00, 0x02, 0x13, 0x01,       // Cipher Suites
        0x01, 0x00,                    // Compression Methods
        // Extensions would follow...
        0x00, 0x05, 0x00, 0x00         // Extensions length and minimal data
    };
    
    flow_tuple_t flow = {};
    flow.ip_version = 4;
    flow.protocol = PROTO_TCP;
    flow.src_ip.v4.addr = inet_addr("192.168.1.100");
    flow.dst_ip.v4.addr = inet_addr("93.184.216.34");
    flow.src_port = 12345;
    flow.dst_port = 443;
    
    traffic_type_t detected_type = traffic_classifier_classify_packet(
        classifier, tls13_hello, sizeof(tls13_hello), &flow);
    
    EXPECT_EQ(detected_type, TRAFFIC_TYPE_TLS);
    
    // Check TLS version detection
    tls_version_t version = traffic_classifier_get_tls_version(
        classifier, tls13_hello, sizeof(tls13_hello));
    EXPECT_EQ(version, TLS_VERSION_1_3);
    
    // Test weak TLS 1.0
    uint8_t tls10_hello[] = {
        0x16, 0x03, 0x01, 0x00, 0x40,  // TLS Record Header
        0x01, 0x00, 0x00, 0x3c,        // Handshake Header
        0x03, 0x01,                    // TLS Version 1.0
        // Minimal data...
        0x00, 0x00, 0x00, 0x00
    };
    
    version = traffic_classifier_get_tls_version(classifier, tls10_hello, sizeof(tls10_hello));
    EXPECT_EQ(version, TLS_VERSION_1_0);
    
    EXPECT_FALSE(traffic_classifier_is_tls_version_secure(version));
    EXPECT_TRUE(traffic_classifier_is_tls_version_secure(TLS_VERSION_1_3));
}

TEST_F(TrafficClassifierTest, QUICDetection) {
    // QUIC Initial packet (simplified)
    uint8_t quic_initial[] = {
        0xc0,                          // Header form (1) + Fixed bit (1) + Packet type (00) + Reserved (00)
        0x00, 0x00, 0x00, 0x01,       // Version (QUIC v1)
        0x08,                          // DCID Length
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, // Destination Connection ID
        0x08,                          // SCID Length  
        0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, // Source Connection ID
        0x00,                          // Token Length (0)
        0x04, 0x00,                    // Length (variable-length integer)
        0x01, 0x02, 0x03, 0x04         // Packet Number and Payload
    };
    
    flow_tuple_t flow = {};
    flow.ip_version = 4;
    flow.protocol = PROTO_UDP;
    flow.src_ip.v4.addr = inet_addr("192.168.1.100");
    flow.dst_ip.v4.addr = inet_addr("172.217.14.100");
    flow.src_port = 12345;
    flow.dst_port = 443;
    
    traffic_type_t detected_type = traffic_classifier_classify_packet(
        classifier, quic_initial, sizeof(quic_initial), &flow);
    
    EXPECT_EQ(detected_type, TRAFFIC_TYPE_QUIC);
    
    // Check QUIC version
    uint32_t quic_version = traffic_classifier_get_quic_version(
        classifier, quic_initial, sizeof(quic_initial));
    EXPECT_EQ(quic_version, 0x00000001); // QUIC v1
    
    // Test QUIC v2
    uint8_t quic_v2[] = {
        0xc0,                          
        0x6b, 0x33, 0x43, 0xcf,       // QUIC v2 version
        0x08,                          
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x08,                            
        0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
        0x00,                          
        0x04, 0x00,                    
        0x01, 0x02, 0x03, 0x04         
    };
    
    quic_version = traffic_classifier_get_quic_version(classifier, quic_v2, sizeof(quic_v2));
    EXPECT_EQ(quic_version, 0x6b3343cf); // QUIC v2
}

TEST_F(TrafficClassifierTest, HTTPSDetection) {
    // HTTP request over TLS (application data)
    uint8_t https_data[] = {
        0x17, 0x03, 0x03, 0x00, 0x50,  // TLS Application Data record
        // Encrypted HTTP data would follow...
        0x47, 0x45, 0x54, 0x20, 0x2f,  // "GET /" (if decrypted)
        0x20, 0x48, 0x54, 0x54, 0x50,  // " HTTP"
        0x2f, 0x31, 0x2e, 0x31, 0x0d,  // "/1.1\r"
        0x0a, 0x48, 0x6f, 0x73, 0x74,  // "\nHost"
    };
    
    flow_tuple_t flow = {};
    flow.ip_version = 4;
    flow.protocol = PROTO_TCP;
    flow.src_ip.v4.addr = inet_addr("192.168.1.100");
    flow.dst_ip.v4.addr = inet_addr("93.184.216.34");
    flow.src_port = 12345;
    flow.dst_port = 443;
    
    traffic_type_t detected_type = traffic_classifier_classify_packet(
        classifier, https_data, sizeof(https_data), &flow);
    
    // Should detect as TLS (encrypted HTTP)
    EXPECT_EQ(detected_type, TRAFFIC_TYPE_TLS);
}

TEST_F(TrafficClassifierTest, PlainHTTPDetection) {
    // Plain HTTP request
    uint8_t http_request[] = {
        "GET / HTTP/1.1\r\n"
        "Host: example.com\r\n"
        "User-Agent: TestClient/1.0\r\n"
        "Accept: text/html\r\n"
        "\r\n"
    };
    
    flow_tuple_t flow = {};
    flow.ip_version = 4;
    flow.protocol = PROTO_TCP;
    flow.src_ip.v4.addr = inet_addr("192.168.1.100");
    flow.dst_ip.v4.addr = inet_addr("93.184.216.34");
    flow.src_port = 12345;
    flow.dst_port = 80;
    
    traffic_type_t detected_type = traffic_classifier_classify_packet(
        classifier, http_request, sizeof(http_request) - 1, &flow);
    
    EXPECT_EQ(detected_type, TRAFFIC_TYPE_HTTP);
}

TEST_F(TrafficClassifierTest, DNSDetection) {
    // DNS query packet
    uint8_t dns_query[] = {
        0x12, 0x34,                    // Transaction ID
        0x01, 0x00,                    // Flags: Standard query
        0x00, 0x01,                    // Questions: 1
        0x00, 0x00,                    // Answer RRs: 0
        0x00, 0x00,                    // Authority RRs: 0
        0x00, 0x00,                    // Additional RRs: 0
        // Query for "example.com" A record
        0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e',
        0x03, 'c', 'o', 'm',
        0x00,                          // Null terminator
        0x00, 0x01,                    // Type: A
        0x00, 0x01                     // Class: IN
    };
    
    flow_tuple_t flow = {};
    flow.ip_version = 4;
    flow.protocol = PROTO_UDP;
    flow.src_ip.v4.addr = inet_addr("192.168.1.100");
    flow.dst_ip.v4.addr = inet_addr("8.8.8.8");
    flow.src_port = 12345;
    flow.dst_port = 53;
    
    traffic_type_t detected_type = traffic_classifier_classify_packet(
        classifier, dns_query, sizeof(dns_query), &flow);
    
    EXPECT_EQ(detected_type, TRAFFIC_TYPE_DNS);
    
    // Test DNS over HTTPS (DoH)
    flow.dst_port = 443;
    flow.protocol = PROTO_TCP;
    
    uint8_t doh_request[] = {
        0x17, 0x03, 0x03, 0x00, 0x30,  // TLS Application Data
        // Would contain encrypted DNS query in HTTP/2
    };
    
    detected_type = traffic_classifier_classify_packet(
        classifier, doh_request, sizeof(doh_request), &flow);
    EXPECT_EQ(detected_type, TRAFFIC_TYPE_TLS); // Encrypted, so appears as TLS
}

TEST_F(TrafficClassifierTest, P2PDetection) {
    // BitTorrent handshake (simplified)
    uint8_t bittorrent[] = {
        0x13,                          // Protocol name length
        'B', 'i', 't', 'T', 'o', 'r', 'r', 'e', 'n', 't', ' ',
        'p', 'r', 'o', 't', 'o', 'c', 'o', 'l',
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Reserved
        // Info hash and peer ID would follow...
    };
    
    flow_tuple_t flow = {};
    flow.ip_version = 4;
    flow.protocol = PROTO_TCP;
    flow.src_ip.v4.addr = inet_addr("192.168.1.100");
    flow.dst_ip.v4.addr = inet_addr("203.0.113.50");
    flow.src_port = 12345;
    flow.dst_port = 6881;
    
    traffic_type_t detected_type = traffic_classifier_classify_packet(
        classifier, bittorrent, sizeof(bittorrent), &flow);
    
    EXPECT_EQ(detected_type, TRAFFIC_TYPE_P2P);
}

TEST_F(TrafficClassifierTest, FlowTracking) {
    flow_tuple_t flow = {};
    flow.ip_version = 4;
    flow.protocol = PROTO_TCP;
    flow.src_ip.v4.addr = inet_addr("192.168.1.100");
    flow.dst_ip.v4.addr = inet_addr("93.184.216.34");
    flow.src_port = 12345;
    flow.dst_port = 443;
    
    // First packet: TLS handshake
    uint8_t tls_handshake[] = {
        0x16, 0x03, 0x03, 0x00, 0x40,
        0x01, 0x00, 0x00, 0x3c,
        0x03, 0x04  // TLS 1.3
    };
    
    traffic_type_t type1 = traffic_classifier_classify_packet(
        classifier, tls_handshake, sizeof(tls_handshake), &flow);
    EXPECT_EQ(type1, TRAFFIC_TYPE_TLS);
    
    // Second packet: Application data (should remember flow as TLS)
    uint8_t app_data[] = {
        0x17, 0x03, 0x03, 0x00, 0x20,
        0x01, 0x02, 0x03, 0x04  // Encrypted data
    };
    
    traffic_type_t type2 = traffic_classifier_classify_packet(
        classifier, app_data, sizeof(app_data), &flow);
    EXPECT_EQ(type2, TRAFFIC_TYPE_TLS);
    
    // Check flow classification
    EXPECT_TRUE(traffic_classifier_is_flow_encrypted(classifier, &flow));
    EXPECT_EQ(traffic_classifier_get_flow_type(classifier, &flow), TRAFFIC_TYPE_TLS);
}

TEST_F(TrafficClassifierTest, Statistics) {
    traffic_stats_t stats;
    traffic_classifier_get_stats(classifier, &stats);
    
    EXPECT_EQ(stats.total_packets_classified, 0);
    EXPECT_EQ(stats.tls_connections, 0);
    EXPECT_EQ(stats.quic_connections, 0);
    EXPECT_EQ(stats.http_connections, 0);
    EXPECT_EQ(stats.unknown_traffic, 0);
    
    // Process some packets
    flow_tuple_t flow = {};
    flow.ip_version = 4;
    flow.protocol = PROTO_TCP;
    flow.dst_port = 443;
    
    uint8_t tls_packet[] = { 0x16, 0x03, 0x03, 0x00, 0x10 };
    for (int i = 0; i < 5; i++) {
        traffic_classifier_classify_packet(classifier, tls_packet, sizeof(tls_packet), &flow);
    }
    
    traffic_classifier_get_stats(classifier, &stats);
    EXPECT_EQ(stats.total_packets_classified, 5);
    EXPECT_GT(stats.tls_connections, 0);
}

TEST_F(TrafficClassifierTest, ConcurrentClassification) {
    const int num_threads = 4;
    const int packets_per_thread = 25;
    std::atomic<int> classifications{0};
    std::vector<std::thread> threads;
    
    auto classify_packets = [&](int thread_id) {
        for (int i = 0; i < packets_per_thread; i++) {
            flow_tuple_t flow = {};
            flow.ip_version = 4;
            flow.protocol = PROTO_TCP;
            flow.src_ip.v4.addr = htonl(0xC0A80100 + thread_id);
            flow.dst_ip.v4.addr = htonl(0x5DB8D822 + i);
            flow.src_port = 1000 + thread_id;
            flow.dst_port = 443;
            
            uint8_t tls_packet[] = { 0x16, 0x03, 0x03, 0x00, 0x10, 0x01, 0x02, 0x03 };
            
            traffic_type_t type = traffic_classifier_classify_packet(
                classifier, tls_packet, sizeof(tls_packet), &flow);
            
            if (type != TRAFFIC_TYPE_UNKNOWN) {
                classifications.fetch_add(1);
            }
        }
    };
    
    // Start threads
    for (int i = 0; i < num_threads; i++) {
        threads.emplace_back(classify_packets, i);
    }
    
    // Wait for completion
    for (auto& t : threads) {
        t.join();
    }
    
    EXPECT_EQ(classifications.load(), num_threads * packets_per_thread);
    
    traffic_stats_t stats;
    traffic_classifier_get_stats(classifier, &stats);
    EXPECT_EQ(stats.total_packets_classified, num_threads * packets_per_thread);
}

TEST_F(TrafficClassifierTest, ErrorHandling) {
    // Test null parameters
    EXPECT_EQ(traffic_classifier_classify_packet(nullptr, nullptr, 0, nullptr), TRAFFIC_TYPE_UNKNOWN);
    
    flow_tuple_t flow = {};
    uint8_t packet[] = { 0x01, 0x02, 0x03, 0x04 };
    
    EXPECT_EQ(traffic_classifier_classify_packet(classifier, nullptr, 0, &flow), TRAFFIC_TYPE_UNKNOWN);
    EXPECT_EQ(traffic_classifier_classify_packet(classifier, packet, 0, &flow), TRAFFIC_TYPE_UNKNOWN);
    EXPECT_EQ(traffic_classifier_classify_packet(classifier, packet, sizeof(packet), nullptr), TRAFFIC_TYPE_UNKNOWN);
    
    // Test operations on null classifier
    EXPECT_EQ(traffic_classifier_get_flow_type(nullptr, &flow), TRAFFIC_TYPE_UNKNOWN);
    EXPECT_FALSE(traffic_classifier_is_flow_encrypted(nullptr, &flow));
    EXPECT_EQ(traffic_classifier_get_tls_version(nullptr, packet, sizeof(packet)), TLS_VERSION_UNKNOWN);
    EXPECT_EQ(traffic_classifier_get_quic_version(nullptr, packet, sizeof(packet)), 0);
    
    traffic_classifier_destroy(nullptr); // Should not crash
}

TEST_F(TrafficClassifierTest, ProtocolStringConversion) {
    EXPECT_STREQ(traffic_type_string(TRAFFIC_TYPE_HTTP), "HTTP");
    EXPECT_STREQ(traffic_type_string(TRAFFIC_TYPE_TLS), "TLS");
    EXPECT_STREQ(traffic_type_string(TRAFFIC_TYPE_QUIC), "QUIC");
    EXPECT_STREQ(traffic_type_string(TRAFFIC_TYPE_DNS), "DNS");
    EXPECT_STREQ(traffic_type_string(TRAFFIC_TYPE_P2P), "P2P");
    EXPECT_STREQ(traffic_type_string(TRAFFIC_TYPE_UNKNOWN), "Unknown");
    
    EXPECT_STREQ(tls_version_string(TLS_VERSION_1_0), "TLS 1.0");
    EXPECT_STREQ(tls_version_string(TLS_VERSION_1_1), "TLS 1.1");
    EXPECT_STREQ(tls_version_string(TLS_VERSION_1_2), "TLS 1.2");
    EXPECT_STREQ(tls_version_string(TLS_VERSION_1_3), "TLS 1.3");
    EXPECT_STREQ(tls_version_string(TLS_VERSION_UNKNOWN), "Unknown");
}

TEST_F(TrafficClassifierTest, PayloadAnalysis) {
    // Test encrypted vs plaintext detection
    uint8_t plaintext[] = "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n";
    uint8_t ciphertext[] = { 0x17, 0x03, 0x03, 0x00, 0x20, 0xab, 0xcd, 0xef, 0x12 };
    
    flow_tuple_t flow = {};
    flow.ip_version = 4;
    flow.protocol = PROTO_TCP;
    flow.dst_port = 80;
    
    EXPECT_FALSE(traffic_classifier_is_payload_encrypted(classifier, plaintext, sizeof(plaintext) - 1));
    EXPECT_TRUE(traffic_classifier_is_payload_encrypted(classifier, ciphertext, sizeof(ciphertext)));
    
    // Test entropy analysis
    double plaintext_entropy = traffic_classifier_calculate_entropy(plaintext, sizeof(plaintext) - 1);
    double ciphertext_entropy = traffic_classifier_calculate_entropy(ciphertext, sizeof(ciphertext));
    
    EXPECT_LT(plaintext_entropy, ciphertext_entropy);
    EXPECT_GT(ciphertext_entropy, 7.0); // High entropy for encrypted data
}