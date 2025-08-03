#ifndef TEST_UTILITIES_H
#define TEST_UTILITIES_H

#include <vector>
#include <string>
#include <chrono>
#include <memory>
#include "api/relative_vpn.h"
#include "core/types.h"

// Test utilities for VPN packet lifecycle testing
namespace TestUtils {

// ======================= Packet Builder Utilities =======================

class PacketBuilder {
public:
    PacketBuilder() = default;
    
    // Create HTTP request packets
    static std::vector<uint8_t> CreateHTTPRequest(
        const std::string& src_ip = "192.168.1.100",
        const std::string& dst_ip = "93.184.216.34",  // example.com
        uint16_t src_port = 12345,
        uint16_t dst_port = 80
    );
    
    // Create HTTPS request packets
    static std::vector<uint8_t> CreateHTTPSRequest(
        const std::string& src_ip = "192.168.1.100", 
        const std::string& dst_ip = "93.184.216.34",
        uint16_t src_port = 12345,
        uint16_t dst_port = 443
    );
    
    // Create DNS query packets
    static std::vector<uint8_t> CreateDNSQuery(
        const std::string& domain,
        const std::string& src_ip = "192.168.1.100",
        const std::string& dns_server = "8.8.8.8",
        uint16_t query_id = 0x1234
    );
    
    // Create video streaming packets (simulates Netflix, YouTube)
    static std::vector<uint8_t> CreateVideoStreamPacket(
        const std::string& src_ip = "192.168.1.100",
        const std::string& dst_ip = "151.101.1.140",  // Reddit CDN example
        uint16_t src_port = 54321,
        uint16_t dst_port = 443
    );
    
    // Create WebRTC STUN packets
    static std::vector<uint8_t> CreateWebRTCSTUNPacket(
        const std::string& src_ip = "192.168.1.100",
        const std::string& stun_server = "74.125.224.127",  // Google STUN
        uint16_t src_port = 54321,
        uint16_t dst_port = 3478
    );
    
    // Create IPv6 packets for NAT64 testing
    static std::vector<uint8_t> CreateIPv6Packet(
        const std::string& src_ipv6 = "fe80::1",
        const std::string& dst_ipv6 = "2001:4860:4860::8888",  // Google DNS IPv6
        uint16_t src_port = 12345,
        uint16_t dst_port = 53
    );
    
private:
    static void AddIPv4Header(std::vector<uint8_t>& packet, 
                             const std::string& src_ip, 
                             const std::string& dst_ip,
                             uint8_t protocol,
                             uint16_t total_length);
    
    static void AddTCPHeader(std::vector<uint8_t>& packet,
                           uint16_t src_port,
                           uint16_t dst_port,
                           uint32_t seq_num = 1000,
                           uint8_t flags = 0x02);  // SYN by default
    
    static void AddUDPHeader(std::vector<uint8_t>& packet,
                           uint16_t src_port,
                           uint16_t dst_port,
                           uint16_t data_length);
};

// ======================= Mock Data Factory =======================

class MockDataFactory {
public:
    // Generate realistic web browsing scenario packets
    static std::vector<std::vector<uint8_t>> GenerateWebBrowsingSession(int num_requests = 10);
    
    // Generate video streaming packets (simulates continuous streaming)
    static std::vector<std::vector<uint8_t>> GenerateVideoStreamingSession(int duration_seconds = 30);
    
    // Generate DNS resolution sequence (query + response simulation)
    static std::vector<std::vector<uint8_t>> GenerateDNSResolutionSequence(const std::vector<std::string>& domains);
    
    // Generate email client packets (IMAP/SMTP)
    static std::vector<std::vector<uint8_t>> GenerateEmailSession();
    
    // Generate social media usage packets (HTTPS to various platforms)
    static std::vector<std::vector<uint8_t>> GenerateSocialMediaSession();
    
    // Generate file download simulation
    static std::vector<std::vector<uint8_t>> GenerateFileDownloadSession(size_t file_size_mb = 10);
};

// ======================= Performance Timer =======================

class PerformanceTimer {
public:
    PerformanceTimer() : start_time_(std::chrono::high_resolution_clock::now()) {}
    
    void Reset() { start_time_ = std::chrono::high_resolution_clock::now(); }
    
    double ElapsedMilliseconds() const {
        auto now = std::chrono::high_resolution_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::microseconds>(now - start_time_);
        return duration.count() / 1000.0;
    }
    
    double ElapsedSeconds() const { return ElapsedMilliseconds() / 1000.0; }
    
    // Calculate throughput metrics
    double CalculatePacketsPerSecond(int packet_count) const {
        double elapsed = ElapsedSeconds();
        return elapsed > 0 ? packet_count / elapsed : 0;
    }
    
    double CalculateMbpsFromBytes(size_t total_bytes) const {
        double elapsed = ElapsedSeconds();
        if (elapsed <= 0) return 0;
        double bits = total_bytes * 8;
        double mbps = (bits / 1000000.0) / elapsed;
        return mbps;
    }
    
private:
    std::chrono::high_resolution_clock::time_point start_time_;
};

// ======================= VPN Test Harness =======================

class VPNTestHarness {
public:
    VPNTestHarness();
    ~VPNTestHarness();
    
    // Setup VPN with optimal configuration for testing
    bool StartVPN(bool enable_nat64 = true, bool enable_privacy_guards = true);
    void StopVPN();
    bool IsRunning() const;
    
    // Inject single packet and verify processing
    bool InjectPacket(const std::vector<uint8_t>& packet);
    
    // Inject packet burst and measure performance
    struct BurstResult {
        int total_packets;
        int successful_injections;
        double elapsed_ms;
        double packets_per_second;
        bool vpn_stable;
    };
    
    BurstResult InjectPacketBurst(const std::vector<std::vector<uint8_t>>& packets);
    
    // Get VPN metrics for validation
    bool GetMetrics(vpn_metrics_t& metrics);
    
    // Validate internet connectivity simulation
    bool ValidateInternetConnectivity();
    
    // Test specific protocols
    bool TestHTTPConnectivity();
    bool TestHTTPSConnectivity();  
    bool TestDNSResolution();
    bool TestVideoStreaming();
    
private:
    vpn_config_t config_;
    bool is_initialized_;
    
    void InitializeConfig();
};

// ======================= Network Simulator =======================

class NetworkSimulator {
public:
    // Simulate various network conditions
    enum NetworkCondition {
        WIFI_EXCELLENT,
        WIFI_GOOD,
        WIFI_POOR,
        CELLULAR_4G,
        CELLULAR_3G,
        CELLULAR_EDGE,
        NO_CONNECTIVITY
    };
    
    static std::vector<std::vector<uint8_t>> SimulateRealWorldTraffic(
        NetworkCondition condition,
        int duration_seconds = 60
    );
    
    // Simulate packet loss and delays
    static std::vector<std::vector<uint8_t>> SimulatePacketLoss(
        const std::vector<std::vector<uint8_t>>& original_packets,
        double loss_percentage = 5.0
    );
    
    // Simulate network congestion
    static std::vector<std::vector<uint8_t>> SimulateNetworkCongestion(
        const std::vector<std::vector<uint8_t>>& original_packets,
        double congestion_factor = 0.7
    );
};

// ======================= Test Validation Helpers =======================

class TestValidator {
public:
    // Validate packet integrity
    static bool ValidatePacketIntegrity(const std::vector<uint8_t>& packet);
    
    // Validate DNS query format
    static bool ValidateDNSQuery(const std::vector<uint8_t>& packet, const std::string& expected_domain);
    
    // Validate HTTP request format  
    static bool ValidateHTTPRequest(const std::vector<uint8_t>& packet);
    
    // Calculate packet checksum
    static uint32_t CalculateChecksum(const std::vector<uint8_t>& packet);
    
    // Validate IP header
    static bool ValidateIPHeader(const std::vector<uint8_t>& packet);
    
    // Check if packet is properly formed
    static bool IsValidPacket(const std::vector<uint8_t>& packet);
};

// ======================= Logging and Debugging =======================

class TestLogger {
public:
    enum LogLevel { DEBUG, INFO, WARN, ERROR };
    
    static void Log(LogLevel level, const std::string& message);
    static void LogPacketInfo(const std::vector<uint8_t>& packet, const std::string& description);
    static void LogPerformanceMetrics(const VPNTestHarness::BurstResult& result);
    static void LogVPNMetrics(const vpn_metrics_t& metrics);
    
    static void SetLogLevel(LogLevel level) { current_level_ = level; }
    
private:
    static LogLevel current_level_;
    static std::string LevelToString(LogLevel level);
};

} // namespace TestUtils

#endif // TEST_UTILITIES_H