#include "test_utilities.h"
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <iostream>
#include <iomanip>
#include <random>
#include <cstring>

extern "C" {
    // Forward declarations to avoid linkage issues
    vpn_status_t vpn_start(const vpn_config_t *config);
    vpn_status_t vpn_stop(void);
    vpn_status_t vpn_inject(const uint8_t *packet, size_t length);
    vpn_status_t vpn_get_metrics(vpn_metrics_t *metrics);
    bool vpn_is_running(void);
}

namespace TestUtils {

// Initialize static members
TestLogger::LogLevel TestLogger::current_level_ = TestLogger::INFO;

// ======================= PacketBuilder Implementation =======================

void PacketBuilder::AddIPv4Header(std::vector<uint8_t>& packet, 
                                  const std::string& src_ip, 
                                  const std::string& dst_ip,
                                  uint8_t protocol,
                                  uint16_t total_length) {
    struct ip ip_header = {};
    ip_header.ip_v = 4;
    ip_header.ip_hl = 5;  // 20 bytes
    ip_header.ip_tos = 0;
    ip_header.ip_len = htons(total_length);
    ip_header.ip_id = htons(rand() % 65536);
    ip_header.ip_off = 0;
    ip_header.ip_ttl = 64;
    ip_header.ip_p = protocol;
    ip_header.ip_src.s_addr = inet_addr(src_ip.c_str());
    ip_header.ip_dst.s_addr = inet_addr(dst_ip.c_str());
    ip_header.ip_sum = 0;  // Will be calculated by stack
    
    const uint8_t* ip_data = reinterpret_cast<const uint8_t*>(&ip_header);
    packet.insert(packet.end(), ip_data, ip_data + sizeof(ip_header));
}

void PacketBuilder::AddTCPHeader(std::vector<uint8_t>& packet,
                                uint16_t src_port,
                                uint16_t dst_port,
                                uint32_t seq_num,
                                uint8_t flags) {
    struct tcphdr tcp_header = {};
    tcp_header.th_sport = htons(src_port);
    tcp_header.th_dport = htons(dst_port);
    tcp_header.th_seq = htonl(seq_num);
    tcp_header.th_ack = 0;
    tcp_header.th_off = 5;  // 20 bytes
    tcp_header.th_flags = flags;
    tcp_header.th_win = htons(8192);
    tcp_header.th_sum = 0;  // Will be calculated by stack
    tcp_header.th_urp = 0;
    
    const uint8_t* tcp_data = reinterpret_cast<const uint8_t*>(&tcp_header);
    packet.insert(packet.end(), tcp_data, tcp_data + sizeof(tcp_header));
}

void PacketBuilder::AddUDPHeader(std::vector<uint8_t>& packet,
                                uint16_t src_port,
                                uint16_t dst_port,
                                uint16_t data_length) {
    struct udphdr udp_header = {};
    udp_header.uh_sport = htons(src_port);
    udp_header.uh_dport = htons(dst_port);
    udp_header.uh_ulen = htons(8 + data_length);  // UDP header + data
    udp_header.uh_sum = 0;  // Will be calculated by stack
    
    const uint8_t* udp_data = reinterpret_cast<const uint8_t*>(&udp_header);
    packet.insert(packet.end(), udp_data, udp_data + sizeof(udp_header));
}

std::vector<uint8_t> PacketBuilder::CreateHTTPRequest(const std::string& src_ip,
                                                     const std::string& dst_ip,
                                                     uint16_t src_port,
                                                     uint16_t dst_port) {
    std::vector<uint8_t> packet;
    
    // HTTP request payload
    std::string http_request = 
        "GET / HTTP/1.1\r\n"
        "Host: example.com\r\n"
        "User-Agent: VPN-Test-Client/1.0\r\n"
        "Accept: text/html,application/xhtml+xml\r\n"
        "Connection: keep-alive\r\n\r\n";
    
    uint16_t total_length = 20 + 20 + http_request.length();  // IP + TCP + HTTP
    
    AddIPv4Header(packet, src_ip, dst_ip, IPPROTO_TCP, total_length);
    AddTCPHeader(packet, src_port, dst_port, 1000, 0x18);  // PSH+ACK flags
    
    // Add HTTP payload
    packet.insert(packet.end(), http_request.begin(), http_request.end());
    
    return packet;
}

std::vector<uint8_t> PacketBuilder::CreateHTTPSRequest(const std::string& src_ip,
                                                      const std::string& dst_ip,
                                                      uint16_t src_port,
                                                      uint16_t dst_port) {
    std::vector<uint8_t> packet;
    
    // TLS handshake simulation (simplified)
    std::vector<uint8_t> tls_handshake = {
        0x16, 0x03, 0x01, 0x00, 0x20,  // TLS record header (Client Hello)
        0x01, 0x00, 0x00, 0x1c,        // Handshake header
        0x03, 0x03,                    // TLS version
        // Random bytes (simplified)
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
        0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
        0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20
    };
    
    uint16_t total_length = 20 + 20 + tls_handshake.size();
    
    AddIPv4Header(packet, src_ip, dst_ip, IPPROTO_TCP, total_length);
    AddTCPHeader(packet, src_port, dst_port, 2000, 0x18);  // PSH+ACK flags
    
    // Add TLS payload
    packet.insert(packet.end(), tls_handshake.begin(), tls_handshake.end());
    
    return packet;
}

std::vector<uint8_t> PacketBuilder::CreateDNSQuery(const std::string& domain,
                                                   const std::string& src_ip,
                                                   const std::string& dns_server,
                                                   uint16_t query_id) {
    std::vector<uint8_t> packet;
    
    // DNS query payload (simplified)
    std::vector<uint8_t> dns_query = {
        static_cast<uint8_t>(query_id >> 8), static_cast<uint8_t>(query_id & 0xFF),  // Transaction ID
        0x01, 0x00,  // Flags (standard query)
        0x00, 0x01,  // Questions
        0x00, 0x00,  // Answer RRs
        0x00, 0x00,  // Authority RRs
        0x00, 0x00,  // Additional RRs
        // Domain name (simplified - just length of domain)
        static_cast<uint8_t>(domain.length())
    };
    
    // Add domain bytes
    dns_query.insert(dns_query.end(), domain.begin(), domain.end());
    dns_query.push_back(0x00);  // Null terminator
    
    // Query type and class
    dns_query.insert(dns_query.end(), {0x00, 0x01, 0x00, 0x01});  // A record, IN class
    
    uint16_t total_length = 20 + 8 + dns_query.size();  // IP + UDP + DNS
    
    AddIPv4Header(packet, src_ip, dns_server, IPPROTO_UDP, total_length);
    AddUDPHeader(packet, 54321, 53, dns_query.size());
    
    // Add DNS payload
    packet.insert(packet.end(), dns_query.begin(), dns_query.end());
    
    return packet;
}

std::vector<uint8_t> PacketBuilder::CreateVideoStreamPacket(const std::string& src_ip,
                                                           const std::string& dst_ip,
                                                           uint16_t src_port,
                                                           uint16_t dst_port) {
    std::vector<uint8_t> packet;
    
    // Simulate video streaming data (random bytes representing video stream)
    std::vector<uint8_t> video_data(1200);  // Typical streaming packet size
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(0, 255);
    
    for (auto& byte : video_data) {
        byte = dis(gen);
    }
    
    uint16_t total_length = 20 + 20 + video_data.size();
    
    AddIPv4Header(packet, src_ip, dst_ip, IPPROTO_TCP, total_length);
    AddTCPHeader(packet, src_port, dst_port, 3000, 0x18);  // PSH+ACK flags
    
    // Add video data
    packet.insert(packet.end(), video_data.begin(), video_data.end());
    
    return packet;
}

std::vector<uint8_t> PacketBuilder::CreateWebRTCSTUNPacket(const std::string& src_ip,
                                                          const std::string& stun_server,
                                                          uint16_t src_port,
                                                          uint16_t dst_port) {
    std::vector<uint8_t> packet;
    
    // STUN binding request (simplified)
    std::vector<uint8_t> stun_request = {
        0x00, 0x01,  // Message type: Binding Request
        0x00, 0x08,  // Message length: 8 bytes
        0x21, 0x12, 0xa4, 0x42,  // Magic cookie
        // Transaction ID (12 bytes)
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c
    };
    
    uint16_t total_length = 20 + 8 + stun_request.size();
    
    AddIPv4Header(packet, src_ip, stun_server, IPPROTO_UDP, total_length);
    AddUDPHeader(packet, src_port, dst_port, stun_request.size());
    
    // Add STUN payload
    packet.insert(packet.end(), stun_request.begin(), stun_request.end());
    
    return packet;
}

// ======================= MockDataFactory Implementation =======================

std::vector<std::vector<uint8_t>> MockDataFactory::GenerateWebBrowsingSession(int num_requests) {
    std::vector<std::vector<uint8_t>> packets;
    
    // Popular websites for realistic testing
    std::vector<std::string> websites = {
        "93.184.216.34",   // example.com
        "172.217.164.196", // google.com  
        "104.16.124.96",   // cloudflare.com
        "140.82.112.4"     // github.com
    };
    
    for (int i = 0; i < num_requests; i++) {
        std::string dst_ip = websites[i % websites.size()];
        
        // Mix of HTTP and HTTPS requests
        if (i % 3 == 0) {
            packets.push_back(PacketBuilder::CreateHTTPRequest("192.168.1.100", dst_ip, 12345 + i, 80));
        } else {
            packets.push_back(PacketBuilder::CreateHTTPSRequest("192.168.1.100", dst_ip, 12345 + i, 443));
        }
        
        // Add DNS queries for domains
        if (i % 4 == 0) {
            packets.push_back(PacketBuilder::CreateDNSQuery("example.com"));
        }
    }
    
    return packets;
}

std::vector<std::vector<uint8_t>> MockDataFactory::GenerateVideoStreamingSession(int duration_seconds) {
    std::vector<std::vector<uint8_t>> packets;
    
    // Video streaming typically sends packets every ~33ms (30 FPS)
    int packets_per_second = 30;
    int total_packets = duration_seconds * packets_per_second;
    
    for (int i = 0; i < total_packets; i++) {
        // Simulate Netflix/YouTube streaming
        packets.push_back(PacketBuilder::CreateVideoStreamPacket(
            "192.168.1.100", 
            "151.101.1.140",  // CDN IP
            54321, 
            443
        ));
    }
    
    return packets;
}

std::vector<std::vector<uint8_t>> MockDataFactory::GenerateDNSResolutionSequence(const std::vector<std::string>& domains) {
    std::vector<std::vector<uint8_t>> packets;
    
    for (const auto& domain : domains) {
        // DNS query
        packets.push_back(PacketBuilder::CreateDNSQuery(domain, "192.168.1.100", "8.8.8.8"));
        
        // Follow up with HTTP request to resolved domain
        packets.push_back(PacketBuilder::CreateHTTPSRequest("192.168.1.100", "93.184.216.34", 12345, 443));
    }
    
    return packets;
}

// ======================= VPNTestHarness Implementation =======================

VPNTestHarness::VPNTestHarness() : is_initialized_(false) {
    InitializeConfig();
}

VPNTestHarness::~VPNTestHarness() {
    StopVPN();
}

void VPNTestHarness::InitializeConfig() {
    memset(&config_, 0, sizeof(config_));
    config_.utun_name = nullptr;
    config_.mtu = 1500;
    config_.tunnel_mtu = 1500;
    config_.ipv4_enabled = true;
    config_.ipv6_enabled = true;
    config_.enable_nat64 = true;
    config_.enable_dns_leak_protection = true;
    config_.enable_ipv6_leak_protection = true;
    config_.enable_kill_switch = false;  // Disabled for testing
    config_.enable_webrtc_leak_protection = true;
    config_.dns_cache_size = 1024;
    config_.metrics_buffer_size = 4096;
    config_.reachability_monitoring = true;
    config_.log_level = const_cast<char*>("INFO");
    config_.dns_servers[0] = inet_addr("8.8.8.8");
    config_.dns_servers[1] = inet_addr("1.1.1.1");
    config_.dns_server_count = 2;
    
    is_initialized_ = true;
}

bool VPNTestHarness::StartVPN(bool enable_nat64, bool enable_privacy_guards) {
    if (!is_initialized_) return false;
    
    config_.enable_nat64 = enable_nat64;
    config_.enable_dns_leak_protection = enable_privacy_guards;
    config_.enable_ipv6_leak_protection = enable_privacy_guards;
    config_.enable_webrtc_leak_protection = enable_privacy_guards;
    
    vpn_status_t result = vpn_start(&config_);
    if (result == VPN_ERROR_PERMISSION) {
        TestLogger::Log(TestLogger::WARN, "VPN start failed due to permissions");
        return false;
    }
    
    return result == VPN_SUCCESS;
}

void VPNTestHarness::StopVPN() {
    if (IsRunning()) {
        vpn_stop();
    }
}

bool VPNTestHarness::IsRunning() const {
    return vpn_is_running();
}

bool VPNTestHarness::InjectPacket(const std::vector<uint8_t>& packet) {
    if (packet.empty() || !IsRunning()) {
        return false;
    }
    
    vpn_status_t result = vpn_inject(packet.data(), packet.size());
    return result == VPN_SUCCESS;
}

VPNTestHarness::BurstResult VPNTestHarness::InjectPacketBurst(const std::vector<std::vector<uint8_t>>& packets) {
    BurstResult result = {};
    result.total_packets = packets.size();
    result.successful_injections = 0;
    result.vpn_stable = IsRunning();
    
    if (!result.vpn_stable) {
        return result;
    }
    
    PerformanceTimer timer;
    
    for (const auto& packet : packets) {
        if (InjectPacket(packet)) {
            result.successful_injections++;
        }
    }
    
    result.elapsed_ms = timer.ElapsedMilliseconds();
    result.packets_per_second = timer.CalculatePacketsPerSecond(result.successful_injections);
    result.vpn_stable = IsRunning();
    
    return result;
}

bool VPNTestHarness::GetMetrics(vpn_metrics_t& metrics) {
    if (!IsRunning()) return false;
    
    vpn_status_t result = vpn_get_metrics(&metrics);
    return result == VPN_SUCCESS;
}

bool VPNTestHarness::ValidateInternetConnectivity() {
    return TestHTTPConnectivity() && TestHTTPSConnectivity() && TestDNSResolution();
}

bool VPNTestHarness::TestHTTPConnectivity() {
    auto http_packet = PacketBuilder::CreateHTTPRequest();
    return InjectPacket(http_packet);
}

bool VPNTestHarness::TestHTTPSConnectivity() {
    auto https_packet = PacketBuilder::CreateHTTPSRequest();
    return InjectPacket(https_packet);
}

bool VPNTestHarness::TestDNSResolution() {
    auto dns_packet = PacketBuilder::CreateDNSQuery("example.com");
    return InjectPacket(dns_packet);
}

bool VPNTestHarness::TestVideoStreaming() {
    auto video_packet = PacketBuilder::CreateVideoStreamPacket();
    return InjectPacket(video_packet);
}

// ======================= TestValidator Implementation =======================

bool TestValidator::ValidatePacketIntegrity(const std::vector<uint8_t>& packet) {
    if (packet.size() < 20) return false;  // Minimum IP header size
    
    // Check IP version
    if ((packet[0] >> 4) != 4) return false;
    
    // Check header length
    uint8_t header_length = (packet[0] & 0x0F) * 4;
    if (header_length < 20 || header_length > packet.size()) return false;
    
    return true;
}

bool TestValidator::ValidateIPHeader(const std::vector<uint8_t>& packet) {
    return ValidatePacketIntegrity(packet);
}

bool TestValidator::IsValidPacket(const std::vector<uint8_t>& packet) {
    return ValidatePacketIntegrity(packet);
}

uint32_t TestValidator::CalculateChecksum(const std::vector<uint8_t>& packet) {
    uint32_t checksum = 0;
    for (uint8_t byte : packet) {
        checksum += byte;
    }
    return checksum;
}

// ======================= TestLogger Implementation =======================

void TestLogger::Log(LogLevel level, const std::string& message) {
    if (level < current_level_) return;
    
    std::cout << "[" << LevelToString(level) << "] " << message << std::endl;
}

void TestLogger::LogPacketInfo(const std::vector<uint8_t>& packet, const std::string& description) {
    if (current_level_ > DEBUG) return;
    
    std::cout << "[DEBUG] " << description << " - Size: " << packet.size() << " bytes" << std::endl;
    
    // Log first 32 bytes in hex
    std::cout << "        Data: ";
    for (size_t i = 0; i < std::min<size_t>(32, packet.size()); i++) {
        std::cout << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(packet[i]) << " ";
    }
    if (packet.size() > 32) std::cout << "...";
    std::cout << std::dec << std::endl;
}

void TestLogger::LogPerformanceMetrics(const VPNTestHarness::BurstResult& result) {
    Log(INFO, "Performance Metrics:");
    Log(INFO, "  Total packets: " + std::to_string(result.total_packets));
    Log(INFO, "  Successful injections: " + std::to_string(result.successful_injections));
    Log(INFO, "  Success rate: " + std::to_string(100.0 * result.successful_injections / result.total_packets) + "%");
    Log(INFO, "  Elapsed time: " + std::to_string(result.elapsed_ms) + "ms");
    Log(INFO, "  Throughput: " + std::to_string(result.packets_per_second) + " packets/sec");
    Log(INFO, "  VPN stable: " + std::string(result.vpn_stable ? "Yes" : "No"));
}

void TestLogger::LogVPNMetrics(const vpn_metrics_t& metrics) {
    Log(INFO, "VPN Metrics:");
    Log(INFO, "  Bytes in: " + std::to_string(metrics.bytes_in));
    Log(INFO, "  Bytes out: " + std::to_string(metrics.bytes_out));
    Log(INFO, "  Packets in: " + std::to_string(metrics.packets_in));
    Log(INFO, "  Packets out: " + std::to_string(metrics.packets_out));
    Log(INFO, "  Active connections: " + std::to_string(metrics.active_connections));
    Log(INFO, "  DNS queries: " + std::to_string(metrics.dns_queries));
    Log(INFO, "  Privacy violations: " + std::to_string(metrics.privacy_violations));
}

std::string TestLogger::LevelToString(LogLevel level) {
    switch (level) {
        case DEBUG: return "DEBUG";
        case INFO: return "INFO";
        case WARN: return "WARN";
        case ERROR: return "ERROR";
        default: return "UNKNOWN";
    }
}

} // namespace TestUtils