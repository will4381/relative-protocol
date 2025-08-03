#ifndef RELATIVE_VPN_TEST_UTILITIES_H
#define RELATIVE_VPN_TEST_UTILITIES_H

#include <gtest/gtest.h>
#include "core/types.h"
#include "api/relative_vpn.h"
#include <vector>
#include <memory>
#include <random>
#include <string>
#include <chrono>
#include <functional>

/**
 * Comprehensive Test Utilities for VPN Framework
 * 
 * Provides:
 * - Packet builders and generators
 * - Mock data factories
 * - Test harness utilities  
 * - Performance measurement tools
 * - Network simulation helpers
 * - Validation and assertion helpers
 */

namespace vpn_test_utils {

// ============================================================================
// Packet Builder Pattern for Test Data Creation
// ============================================================================

class PacketBuilder {
public:
    PacketBuilder();
    ~PacketBuilder() = default;
    
    // Protocol setters
    PacketBuilder& ipv4(const std::string& src_ip, const std::string& dst_ip);
    PacketBuilder& ipv6(const std::string& src_ip, const std::string& dst_ip);
    PacketBuilder& tcp(uint16_t src_port, uint16_t dst_port);
    PacketBuilder& udp(uint16_t src_port, uint16_t dst_port);
    PacketBuilder& icmp(uint8_t type, uint8_t code);
    
    // Payload setters
    PacketBuilder& payload(const uint8_t* data, size_t size);
    PacketBuilder& payload(const std::string& data);
    PacketBuilder& random_payload(size_t size);
    
    // Options
    PacketBuilder& mtu(uint16_t mtu_size);
    PacketBuilder& ttl(uint8_t time_to_live);
    PacketBuilder& fragmented(bool enable);
    PacketBuilder& malformed(bool enable);
    
    // Build methods
    packet_info_t build();
    std::vector<uint8_t> build_raw();
    
    // Reset for reuse
    PacketBuilder& reset();
    
private:
    struct BuilderState;
    std::unique_ptr<BuilderState> state_;
    
    void build_ipv4_header(std::vector<uint8_t>& packet);
    void build_ipv6_header(std::vector<uint8_t>& packet);
    void build_tcp_header(std::vector<uint8_t>& packet);
    void build_udp_header(std::vector<uint8_t>& packet);
    void build_icmp_header(std::vector<uint8_t>& packet);
    uint16_t calculate_checksum(const uint8_t* data, size_t length);
};

// ============================================================================
// Mock Data Factories
// ============================================================================

class MockDataFactory {
public:
    MockDataFactory();
    
    // VPN Configuration Mocks
    vpn_config_t create_default_config();
    vpn_config_t create_minimal_config();
    vpn_config_t create_secure_config();
    vpn_config_t create_performance_config();
    vpn_config_t create_ios_config();
    vpn_config_t create_invalid_config(); // For error testing
    
    // Packet Data Mocks
    std::vector<packet_info_t> create_web_browsing_session();
    std::vector<packet_info_t> create_video_streaming_session();
    std::vector<packet_info_t> create_dns_query_session();
    std::vector<packet_info_t> create_mixed_protocol_session();
    std::vector<packet_info_t> create_malicious_packet_set();
    
    // Network Scenario Mocks
    struct NetworkScenario {
        std::string name;
        std::vector<packet_info_t> packets;
        std::function<bool(const vpn_metrics_t&)> validation;
    };
    
    std::vector<NetworkScenario> create_common_scenarios();
    NetworkScenario create_dos_attack_scenario();
    NetworkScenario create_memory_exhaustion_scenario();
    NetworkScenario create_protocol_fuzzing_scenario();
    
    // Certificate and TLS Mocks
    std::vector<uint8_t> create_valid_certificate();
    std::vector<uint8_t> create_malformed_certificate();
    std::vector<uint8_t> create_expired_certificate();
    std::vector<uint8_t> create_tls_handshake_packet();
    
private:
    std::mt19937 rng_;
    uint16_t next_packet_id_;
    
    packet_info_t create_http_request(const std::string& host, const std::string& path);
    packet_info_t create_dns_query(const std::string& domain);
    packet_info_t create_tcp_syn(const std::string& dst_ip, uint16_t dst_port);
};

// ============================================================================
// Performance Measurement Tools
// ============================================================================

class PerformanceTimer {
public:
    PerformanceTimer();
    
    void start();
    void stop();
    void reset();
    
    double elapsed_seconds() const;
    double elapsed_milliseconds() const;
    double elapsed_microseconds() const;
    double elapsed_nanoseconds() const;
    
    // Statistical measurements
    void record_sample();
    double average_time() const;
    double min_time() const;
    double max_time() const;
    double standard_deviation() const;
    size_t sample_count() const;
    
private:
    std::chrono::high_resolution_clock::time_point start_time_;
    std::chrono::high_resolution_clock::time_point end_time_;
    std::vector<double> samples_;
    bool running_;
};

class ThroughputMeter {
public:
    ThroughputMeter();
    
    void start();
    void stop();
    void record_bytes(size_t bytes);
    void record_packets(size_t packets);
    
    double bytes_per_second() const;
    double packets_per_second() const;
    double mbps() const;
    double total_bytes() const;
    double total_packets() const;
    
private:
    std::chrono::steady_clock::time_point start_time_;
    std::chrono::steady_clock::time_point end_time_;
    size_t total_bytes_;
    size_t total_packets_;
    bool running_;
};

// ============================================================================
// VPN Test Harness
// ============================================================================

class VPNTestHarness {
public:
    VPNTestHarness();
    ~VPNTestHarness();
    
    // Setup and teardown
    bool setup(const vpn_config_t& config);
    void teardown();
    
    // Packet injection and processing
    bool inject_packet(const packet_info_t& packet);
    bool inject_packets(const std::vector<packet_info_t>& packets);
    void process_packets(int timeout_ms = 1000);
    
    // State queries
    bool is_running() const;
    vpn_metrics_t get_metrics() const;
    vpn_config_t get_config() const;
    
    // Event handlers
    void set_packet_handler(std::function<void(const packet_info_t&)> handler);
    void set_metrics_handler(std::function<void(const vpn_metrics_t&)> handler);
    void set_error_handler(std::function<void(const std::string&)> handler);
    
    // Validation helpers
    bool wait_for_packet_count(int expected_count, int timeout_ms = 5000);
    bool wait_for_metric_condition(std::function<bool(const vpn_metrics_t&)> condition, int timeout_ms = 5000);
    
    // Configuration management
    bool update_config(const vpn_config_t& new_config);
    bool restart_with_config(const vpn_config_t& new_config);
    
private:
    vpn_result_t result_;
    std::function<void(const packet_info_t&)> packet_handler_;
    std::function<void(const vpn_metrics_t&)> metrics_handler_;
    std::function<void(const std::string&)> error_handler_;
};

// ============================================================================
// Network Simulation Helpers
// ============================================================================

class NetworkSimulator {
public:
    NetworkSimulator();
    
    // Network conditions
    void set_latency(int milliseconds);
    void set_packet_loss(double percentage);
    void set_bandwidth_limit(double mbps);
    void set_jitter(int milliseconds);
    
    // Network events
    void simulate_network_disconnect();
    void simulate_network_reconnect();
    void simulate_network_congestion();
    void simulate_cellular_to_wifi_transition();
    
    // Packet modification
    packet_info_t add_latency(const packet_info_t& packet);
    bool should_drop_packet(); // Based on packet loss rate
    packet_info_t add_jitter(const packet_info_t& packet);
    
private:
    int latency_ms_;
    double packet_loss_rate_;
    double bandwidth_mbps_;
    int jitter_ms_;
    std::mt19937 rng_;
    std::bernoulli_distribution loss_distribution_;
    std::normal_distribution<double> jitter_distribution_;
};

// ============================================================================
// Validation and Assertion Helpers
// ============================================================================

class VPNAssertions {
public:
    // Packet validation
    static bool is_valid_ipv4_packet(const packet_info_t& packet);
    static bool is_valid_ipv6_packet(const packet_info_t& packet);
    static bool is_valid_tcp_packet(const packet_info_t& packet);
    static bool is_valid_udp_packet(const packet_info_t& packet);
    
    // Flow validation
    static bool flows_match(const flow_tuple_t& expected, const flow_tuple_t& actual);
    static bool packet_integrity_preserved(const packet_info_t& original, const packet_info_t& processed);
    
    // Metrics validation
    static bool metrics_are_reasonable(const vpn_metrics_t& metrics);
    static bool performance_meets_requirements(const vpn_metrics_t& metrics, double min_throughput_mbps);
    static bool security_violations_within_limits(const vpn_metrics_t& metrics, int max_violations);
    
    // Configuration validation
    static bool config_is_valid(const vpn_config_t& config);
    static bool config_changes_applied(const vpn_config_t& expected, const vpn_config_t& actual);
};

// ============================================================================
// Memory and Resource Tracking
// ============================================================================

class ResourceTracker {
public:
    ResourceTracker();
    ~ResourceTracker();
    
    void start_tracking();
    void stop_tracking();
    
    size_t get_peak_memory_usage() const;
    size_t get_current_memory_usage() const;
    double get_average_memory_usage() const;
    
    int get_file_descriptor_count() const;
    int get_thread_count() const;
    
    bool has_memory_leaks() const;
    bool has_resource_leaks() const;
    
    void print_resource_summary() const;
    
private:
    struct ResourceState;
    std::unique_ptr<ResourceState> state_;
    
    void sample_resources();
};

// ============================================================================
// Test Data Generators
// ============================================================================

class TestDataGenerator {
public:
    TestDataGenerator(uint32_t seed = 0);
    
    // Random data generation
    std::vector<uint8_t> random_bytes(size_t count);
    std::string random_string(size_t length);
    std::string random_domain_name();
    std::string random_ipv4_address();
    std::string random_ipv6_address();
    uint16_t random_port();
    
    // Realistic data generation
    std::string generate_http_request();
    std::string generate_dns_query();
    std::vector<uint8_t> generate_tls_client_hello();
    std::vector<uint8_t> generate_certificate_request();
    
    // Malicious data generation
    std::vector<uint8_t> generate_buffer_overflow_payload(size_t size);
    std::vector<uint8_t> generate_format_string_payload();
    std::vector<uint8_t> generate_malformed_asn1_data();
    
private:
    std::mt19937 rng_;
    std::uniform_int_distribution<uint8_t> byte_dist_;
    std::uniform_int_distribution<char> char_dist_;
};

// ============================================================================
// Custom Google Test Matchers
// ============================================================================

// Packet matching
MATCHER_P(PacketHasProtocol, protocol, "") {
    return arg.flow.protocol == protocol;
}

MATCHER_P2(PacketHasPorts, src_port, dst_port, "") {
    return arg.flow.src_port == src_port && arg.flow.dst_port == dst_port;
}

MATCHER_P(PacketSizeInRange, size_range, "") {
    return arg.length >= size_range.first && arg.length <= size_range.second;
}

// Metrics matching
MATCHER_P(MetricsHaveMinThroughput, min_mbps, "") {
    double throughput = (arg.bytes_received * 8.0) / (arg.uptime_seconds * 1000000.0);
    return throughput >= min_mbps;
}

MATCHER_P(MetricsHaveMaxErrors, max_errors, "") {
    return arg.packet_errors <= max_errors;
}

// ============================================================================
// Utility Functions
// ============================================================================

// String utilities
std::string bytes_to_hex(const uint8_t* data, size_t length);
std::vector<uint8_t> hex_to_bytes(const std::string& hex);
std::string format_packet_info(const packet_info_t& packet);
std::string format_metrics(const vpn_metrics_t& metrics);

// Time utilities
uint64_t current_time_ns();
uint64_t current_time_ms();
void sleep_ms(int milliseconds);

// Network utilities
bool is_valid_ipv4(const std::string& ip);
bool is_valid_ipv6(const std::string& ip);
uint32_t ipv4_string_to_addr(const std::string& ip);
std::string ipv4_addr_to_string(uint32_t addr);

// File utilities
bool file_exists(const std::string& path);
std::string read_file_to_string(const std::string& path);
bool write_string_to_file(const std::string& content, const std::string& path);

// Process utilities
int get_process_memory_mb();
int get_process_thread_count();
int get_process_fd_count();

} // namespace vpn_test_utils

#endif // RELATIVE_VPN_TEST_UTILITIES_H