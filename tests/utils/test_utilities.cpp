#include "test_utilities.h"
#include <algorithm>
#include <numeric>
#include <cmath>
#include <sstream>
#include <iomanip>
#include <fstream>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>

#ifdef __APPLE__
#include <mach/mach.h>
#include <sys/resource.h>
#endif

namespace vpn_test_utils {

// ============================================================================
// PacketBuilder Implementation
// ============================================================================

struct PacketBuilder::BuilderState {
    uint8_t ip_version = 4;
    std::string src_ip = "10.0.0.1";
    std::string dst_ip = "8.8.8.8";
    uint8_t protocol = PROTO_UDP;
    uint16_t src_port = 12345;
    uint16_t dst_port = 53;
    uint8_t icmp_type = 8;
    uint8_t icmp_code = 0;
    std::vector<uint8_t> payload_data;
    uint16_t mtu_size = 1500;
    uint8_t time_to_live = 64;
    bool is_fragmented = false;
    bool is_malformed = false;
    uint16_t packet_id = 1;
};

PacketBuilder::PacketBuilder() : state_(std::make_unique<BuilderState>()) {}

PacketBuilder& PacketBuilder::ipv4(const std::string& src_ip, const std::string& dst_ip) {
    state_->ip_version = 4;
    state_->src_ip = src_ip;
    state_->dst_ip = dst_ip;
    return *this;
}

PacketBuilder& PacketBuilder::ipv6(const std::string& src_ip, const std::string& dst_ip) {
    state_->ip_version = 6;
    state_->src_ip = src_ip;
    state_->dst_ip = dst_ip;
    return *this;
}

PacketBuilder& PacketBuilder::tcp(uint16_t src_port, uint16_t dst_port) {
    state_->protocol = PROTO_TCP;
    state_->src_port = src_port;
    state_->dst_port = dst_port;
    return *this;
}

PacketBuilder& PacketBuilder::udp(uint16_t src_port, uint16_t dst_port) {
    state_->protocol = PROTO_UDP;
    state_->src_port = src_port;
    state_->dst_port = dst_port;
    return *this;
}

PacketBuilder& PacketBuilder::icmp(uint8_t type, uint8_t code) {
    state_->protocol = PROTO_ICMP;
    state_->icmp_type = type;
    state_->icmp_code = code;
    return *this;
}

PacketBuilder& PacketBuilder::payload(const uint8_t* data, size_t size) {
    state_->payload_data.assign(data, data + size);
    return *this;
}

PacketBuilder& PacketBuilder::payload(const std::string& data) {
    state_->payload_data.assign(data.begin(), data.end());
    return *this;
}

PacketBuilder& PacketBuilder::random_payload(size_t size) {
    state_->payload_data.resize(size);
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<uint8_t> dist(0, 255);
    
    for (size_t i = 0; i < size; i++) {
        state_->payload_data[i] = dist(gen);
    }
    return *this;
}

PacketBuilder& PacketBuilder::mtu(uint16_t mtu_size) {
    state_->mtu_size = mtu_size;
    return *this;
}

PacketBuilder& PacketBuilder::ttl(uint8_t time_to_live) {
    state_->time_to_live = time_to_live;
    return *this;
}

PacketBuilder& PacketBuilder::fragmented(bool enable) {
    state_->is_fragmented = enable;
    return *this;
}

PacketBuilder& PacketBuilder::malformed(bool enable) {
    state_->is_malformed = enable;
    return *this;
}

packet_info_t PacketBuilder::build() {
    std::vector<uint8_t> raw_packet = build_raw();
    
    packet_info_t packet = {};
    packet.data = raw_packet.data();
    packet.length = raw_packet.size();
    packet.flow.ip_version = state_->ip_version;
    packet.flow.protocol = state_->protocol;
    packet.flow.src_port = state_->src_port;
    packet.flow.dst_port = state_->dst_port;
    packet.timestamp_ns = current_time_ns();
    
    if (state_->ip_version == 4) {
        packet.flow.src_ip.v4.addr = ipv4_string_to_addr(state_->src_ip);
        packet.flow.dst_ip.v4.addr = ipv4_string_to_addr(state_->dst_ip);
    }
    
    return packet;
}

std::vector<uint8_t> PacketBuilder::build_raw() {
    std::vector<uint8_t> packet;
    
    if (state_->ip_version == 4) {
        build_ipv4_header(packet);
    } else {
        build_ipv6_header(packet);
    }
    
    switch (state_->protocol) {
        case PROTO_TCP:
            build_tcp_header(packet);
            break;
        case PROTO_UDP:
            build_udp_header(packet);
            break;
        case PROTO_ICMP:
            build_icmp_header(packet);
            break;
    }
    
    // Add payload
    packet.insert(packet.end(), state_->payload_data.begin(), state_->payload_data.end());
    
    // Apply malformation if requested
    if (state_->is_malformed) {
        if (!packet.empty()) {
            packet[packet.size() / 2] = 0xFF; // Corrupt middle byte
        }
    }
    
    return packet;
}

PacketBuilder& PacketBuilder::reset() {
    state_ = std::make_unique<BuilderState>();
    return *this;
}

void PacketBuilder::build_ipv4_header(std::vector<uint8_t>& packet) {
    struct ip header = {};
    header.ip_v = 4;
    header.ip_hl = 5;
    header.ip_tos = 0;
    header.ip_len = htons(sizeof(struct ip) + 
                         (state_->protocol == PROTO_TCP ? sizeof(struct tcphdr) : 
                          state_->protocol == PROTO_UDP ? sizeof(struct udphdr) : 
                          sizeof(struct icmp)) + state_->payload_data.size());
    header.ip_id = htons(state_->packet_id++);
    header.ip_off = state_->is_fragmented ? htons(IP_MF) : 0;
    header.ip_ttl = state_->time_to_live;
    header.ip_p = state_->protocol;
    header.ip_sum = 0;
    inet_pton(AF_INET, state_->src_ip.c_str(), &header.ip_src);
    inet_pton(AF_INET, state_->dst_ip.c_str(), &header.ip_dst);
    
    // Calculate checksum
    header.ip_sum = calculate_checksum(reinterpret_cast<const uint8_t*>(&header), sizeof(header));
    
    const uint8_t* header_bytes = reinterpret_cast<const uint8_t*>(&header);
    packet.insert(packet.end(), header_bytes, header_bytes + sizeof(header));
}

void PacketBuilder::build_ipv6_header(std::vector<uint8_t>& packet) {
    // IPv6 header (simplified)
    uint8_t ipv6_header[40] = {0};
    ipv6_header[0] = 0x60; // Version 6
    
    // Payload length
    uint16_t payload_len = (state_->protocol == PROTO_TCP ? sizeof(struct tcphdr) : 
                           state_->protocol == PROTO_UDP ? sizeof(struct udphdr) : 8) + 
                           state_->payload_data.size();
    ipv6_header[4] = (payload_len >> 8) & 0xFF;
    ipv6_header[5] = payload_len & 0xFF;
    
    // Next header
    ipv6_header[6] = state_->protocol;
    
    // Hop limit
    ipv6_header[7] = state_->time_to_live;
    
    // Source and destination addresses (simplified)
    inet_pton(AF_INET6, state_->src_ip.c_str(), &ipv6_header[8]);
    inet_pton(AF_INET6, state_->dst_ip.c_str(), &ipv6_header[24]);
    
    packet.insert(packet.end(), ipv6_header, ipv6_header + 40);
}

void PacketBuilder::build_tcp_header(std::vector<uint8_t>& packet) {
    struct tcphdr header = {};
    header.th_sport = htons(state_->src_port);
    header.th_dport = htons(state_->dst_port);
    header.th_seq = htonl(12345);
    header.th_ack = 0;
    header.th_off = 5;
    header.th_flags = TH_SYN;
    header.th_win = htons(65535);
    header.th_sum = 0;
    header.th_urp = 0;
    
    const uint8_t* header_bytes = reinterpret_cast<const uint8_t*>(&header);
    packet.insert(packet.end(), header_bytes, header_bytes + sizeof(header));
}

void PacketBuilder::build_udp_header(std::vector<uint8_t>& packet) {
    struct udphdr header = {};
    header.uh_sport = htons(state_->src_port);
    header.uh_dport = htons(state_->dst_port);
    header.uh_ulen = htons(sizeof(struct udphdr) + state_->payload_data.size());
    header.uh_sum = 0;
    
    const uint8_t* header_bytes = reinterpret_cast<const uint8_t*>(&header);
    packet.insert(packet.end(), header_bytes, header_bytes + sizeof(header));
}

void PacketBuilder::build_icmp_header(std::vector<uint8_t>& packet) {
    struct icmp header = {};
    header.icmp_type = state_->icmp_type;
    header.icmp_code = state_->icmp_code;
    header.icmp_cksum = 0;
    header.icmp_id = htons(getpid());
    header.icmp_seq = htons(1);
    
    const uint8_t* header_bytes = reinterpret_cast<const uint8_t*>(&header);
    packet.insert(packet.end(), header_bytes, header_bytes + sizeof(header));
}

uint16_t PacketBuilder::calculate_checksum(const uint8_t* data, size_t length) {
    uint32_t sum = 0;
    
    // Sum 16-bit words
    for (size_t i = 0; i < length - 1; i += 2) {
        sum += (data[i] << 8) + data[i + 1];
    }
    
    // Add odd byte if present
    if (length % 2 == 1) {
        sum += data[length - 1] << 8;
    }
    
    // Fold carry bits
    while (sum >> 16) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    
    return ~sum;
}

// ============================================================================
// MockDataFactory Implementation
// ============================================================================

MockDataFactory::MockDataFactory() : rng_(std::random_device{}()), next_packet_id_(1) {}

vpn_config_t MockDataFactory::create_default_config() {
    vpn_config_t config = {};
    config.utun_name = nullptr;
    config.mtu = 1500;
    config.tunnel_mtu = 1500;
    config.ipv4_enabled = true;
    config.ipv6_enabled = true;
    config.enable_nat64 = false;
    config.enable_dns_leak_protection = true;
    config.enable_ipv6_leak_protection = true;
    config.enable_kill_switch = false;
    config.enable_webrtc_leak_protection = true;
    config.dns_servers[0] = inet_addr("8.8.8.8");
    config.dns_servers[1] = inet_addr("1.1.1.1");
    config.dns_server_count = 2;
    config.dns_cache_size = 1024;
    config.metrics_buffer_size = 4096;
    config.reachability_monitoring = true;
    config.log_level = const_cast<char*>("INFO");
    return config;
}

vpn_config_t MockDataFactory::create_minimal_config() {
    vpn_config_t config = {};
    config.utun_name = nullptr;
    config.mtu = 1280;
    config.tunnel_mtu = 1280;
    config.ipv4_enabled = true;
    config.ipv6_enabled = false;
    config.dns_servers[0] = inet_addr("8.8.8.8");
    config.dns_server_count = 1;
    config.dns_cache_size = 256;
    config.metrics_buffer_size = 1024;
    config.log_level = const_cast<char*>("ERROR");
    return config;
}

vpn_config_t MockDataFactory::create_secure_config() {
    vpn_config_t config = create_default_config();
    config.enable_kill_switch = true;
    config.enable_dns_leak_protection = true;
    config.enable_ipv6_leak_protection = true;
    config.enable_webrtc_leak_protection = true;
    return config;
}

vpn_config_t MockDataFactory::create_performance_config() {
    vpn_config_t config = create_default_config();
    config.mtu = 9000; // Jumbo frames
    config.tunnel_mtu = 9000;
    config.dns_cache_size = 4096;
    config.metrics_buffer_size = 16384;
    config.enable_kill_switch = false; // Reduce overhead
    return config;
}

vpn_config_t MockDataFactory::create_ios_config() {
    vpn_config_t config = create_default_config();
    config.mtu = 1500;
    config.tunnel_mtu = 1500;
    config.enable_kill_switch = true;
    config.dns_cache_size = 512; // Conservative for mobile
    config.metrics_buffer_size = 2048;
    config.reachability_monitoring = true;
    return config;
}

vpn_config_t MockDataFactory::create_invalid_config() {
    vpn_config_t config = {};
    config.mtu = 0; // Invalid MTU
    config.tunnel_mtu = 100; // Too small
    config.ipv4_enabled = false;
    config.ipv6_enabled = false; // No protocols enabled
    config.dns_server_count = 0; // No DNS servers
    config.dns_cache_size = 0; // Invalid cache size
    return config;
}

// ============================================================================
// PerformanceTimer Implementation
// ============================================================================

PerformanceTimer::PerformanceTimer() : running_(false) {}

void PerformanceTimer::start() {
    start_time_ = std::chrono::high_resolution_clock::now();
    running_ = true;
}

void PerformanceTimer::stop() {
    if (running_) {
        end_time_ = std::chrono::high_resolution_clock::now();
        running_ = false;
    }
}

void PerformanceTimer::reset() {
    samples_.clear();
    running_ = false;
}

double PerformanceTimer::elapsed_seconds() const {
    auto end = running_ ? std::chrono::high_resolution_clock::now() : end_time_;
    return std::chrono::duration<double>(end - start_time_).count();
}

double PerformanceTimer::elapsed_milliseconds() const {
    return elapsed_seconds() * 1000.0;
}

double PerformanceTimer::elapsed_microseconds() const {
    return elapsed_seconds() * 1000000.0;
}

double PerformanceTimer::elapsed_nanoseconds() const {
    return elapsed_seconds() * 1000000000.0;
}

void PerformanceTimer::record_sample() {
    if (!running_) {
        samples_.push_back(elapsed_seconds());
    }
}

double PerformanceTimer::average_time() const {
    if (samples_.empty()) return 0.0;
    return std::accumulate(samples_.begin(), samples_.end(), 0.0) / samples_.size();
}

double PerformanceTimer::min_time() const {
    if (samples_.empty()) return 0.0;
    return *std::min_element(samples_.begin(), samples_.end());
}

double PerformanceTimer::max_time() const {
    if (samples_.empty()) return 0.0;
    return *std::max_element(samples_.begin(), samples_.end());
}

double PerformanceTimer::standard_deviation() const {
    if (samples_.size() < 2) return 0.0;
    
    double mean = average_time();
    double variance = 0.0;
    
    for (double sample : samples_) {
        variance += (sample - mean) * (sample - mean);
    }
    
    variance /= samples_.size() - 1;
    return std::sqrt(variance);
}

size_t PerformanceTimer::sample_count() const {
    return samples_.size();
}

// ============================================================================
// Utility Functions Implementation
// ============================================================================

std::string bytes_to_hex(const uint8_t* data, size_t length) {
    std::stringstream ss;
    ss << std::hex << std::setfill('0');
    for (size_t i = 0; i < length; i++) {
        ss << std::setw(2) << static_cast<int>(data[i]);
    }
    return ss.str();
}

std::vector<uint8_t> hex_to_bytes(const std::string& hex) {
    std::vector<uint8_t> bytes;
    for (size_t i = 0; i < hex.length(); i += 2) {
        std::string byte_string = hex.substr(i, 2);
        uint8_t byte = static_cast<uint8_t>(std::strtol(byte_string.c_str(), nullptr, 16));
        bytes.push_back(byte);
    }
    return bytes;
}

std::string format_packet_info(const packet_info_t& packet) {
    std::stringstream ss;
    ss << "Packet[";
    ss << "len=" << packet.length;
    ss << ", proto=" << static_cast<int>(packet.flow.protocol);
    ss << ", src_port=" << packet.flow.src_port;
    ss << ", dst_port=" << packet.flow.dst_port;
    ss << ", ip_v=" << static_cast<int>(packet.flow.ip_version);
    ss << "]";
    return ss.str();
}

std::string format_metrics(const vpn_metrics_t& metrics) {
    std::stringstream ss;
    ss << "Metrics[";
    ss << "packets_in=" << metrics.packets_in;
    ss << ", packets_out=" << metrics.packets_out;
    ss << ", bytes_in=" << metrics.bytes_in;
    ss << ", bytes_out=" << metrics.bytes_out;
    ss << ", errors=" << metrics.packet_errors;
    ss << ", uptime=" << metrics.uptime_seconds << "s";
    ss << "]";
    return ss.str();
}

uint64_t current_time_ns() {
    auto now = std::chrono::high_resolution_clock::now();
    auto duration = now.time_since_epoch();
    return std::chrono::duration_cast<std::chrono::nanoseconds>(duration).count();
}

uint64_t current_time_ms() {
    auto now = std::chrono::high_resolution_clock::now();
    auto duration = now.time_since_epoch();
    return std::chrono::duration_cast<std::chrono::milliseconds>(duration).count();
}

void sleep_ms(int milliseconds) {
    std::this_thread::sleep_for(std::chrono::milliseconds(milliseconds));
}

bool is_valid_ipv4(const std::string& ip) {
    struct sockaddr_in sa;
    return inet_pton(AF_INET, ip.c_str(), &(sa.sin_addr)) != 0;
}

bool is_valid_ipv6(const std::string& ip) {
    struct sockaddr_in6 sa;
    return inet_pton(AF_INET6, ip.c_str(), &(sa.sin6_addr)) != 0;
}

uint32_t ipv4_string_to_addr(const std::string& ip) {
    struct in_addr addr;
    if (inet_pton(AF_INET, ip.c_str(), &addr) == 1) {
        return addr.s_addr;
    }
    return 0;
}

std::string ipv4_addr_to_string(uint32_t addr) {
    struct in_addr in_addr;
    in_addr.s_addr = addr;
    char str[INET_ADDRSTRLEN];
    if (inet_ntop(AF_INET, &in_addr, str, INET_ADDRSTRLEN)) {
        return std::string(str);
    }
    return "";
}

bool file_exists(const std::string& path) {
    std::ifstream file(path);
    return file.good();
}

std::string read_file_to_string(const std::string& path) {
    std::ifstream file(path);
    if (!file.is_open()) {
        return "";
    }
    
    std::stringstream buffer;
    buffer << file.rdbuf();
    return buffer.str();
}

bool write_string_to_file(const std::string& content, const std::string& path) {
    std::ofstream file(path);
    if (!file.is_open()) {
        return false;
    }
    
    file << content;
    return file.good();
}

int get_process_memory_mb() {
#ifdef __APPLE__
    struct mach_task_basic_info info;
    mach_msg_type_number_t info_count = MACH_TASK_BASIC_INFO_COUNT;
    
    if (task_info(mach_task_self(), MACH_TASK_BASIC_INFO,
                  (task_info_t)&info, &info_count) == KERN_SUCCESS) {
        return static_cast<int>(info.resident_size / (1024 * 1024));
    }
#endif
    return -1;
}

int get_process_thread_count() {
#ifdef __APPLE__
    struct task_basic_info info;
    mach_msg_type_number_t info_count = TASK_BASIC_INFO_COUNT;
    
    if (task_info(mach_task_self(), TASK_BASIC_INFO,
                  (task_info_t)&info, &info_count) == KERN_SUCCESS) {
        return info.virtual_size;
    }
#endif
    return -1;
}

int get_process_fd_count() {
    struct rlimit rl;
    if (getrlimit(RLIMIT_NOFILE, &rl) == 0) {
        return static_cast<int>(rl.rlim_cur);
    }
    return -1;
}

} // namespace vpn_test_utils