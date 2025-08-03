#include <stdint.h>
#include <stddef.h>
#include <string.h>

extern "C" {
#include "packet/utun.h"
#include "dns/resolver.h"
#include "nat64/translator.h"
#include "classifier/tls_quic.h"
#include "privacy/guards.h"
#include "core/types.h"
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 20) { // Minimum IP packet size
        return 0;
    }
    
    // Test packet parsing
    packet_info_t packet_info = {0};
    packet_info.data = const_cast<uint8_t*>(data);
    packet_info.length = size;
    packet_info.timestamp_ns = 0;
    
    // Extract basic packet information
    uint8_t ip_version = (data[0] >> 4) & 0x0F;
    packet_info.flow.ip_version = ip_version;
    
    // Test DNS packet parsing
    if (size >= 12) { // Minimum DNS header size
        dns_response_t dns_response = {0};
        dns_parse_packet(data, size, &dns_response);
        dns_response_destroy(&dns_response);
    }
    
    // Test NAT64 validation
    if (ip_version == 4) {
        nat64_validate_ipv4_packet(data, size);
    } else if (ip_version == 6) {
        nat64_validate_ipv6_packet(data, size);
    }
    
    // Test traffic classification
    traffic_classifier_t *classifier = traffic_classifier_create();
    if (classifier) {
        flow_tuple_t flow = {0};
        flow.ip_version = ip_version;
        
        if (size >= 20 && ip_version == 4) {
            flow.protocol = data[9];
            if (flow.protocol == 6 && size >= 40) { // TCP
                flow.src_port = (data[20] << 8) | data[21];
                flow.dst_port = (data[22] << 8) | data[23];
            } else if (flow.protocol == 17 && size >= 28) { // UDP
                flow.src_port = (data[20] << 8) | data[21];
                flow.dst_port = (data[22] << 8) | data[23];
            }
        }
        
        traffic_classification_t classification;
        traffic_classifier_analyze_packet(classifier, data, size, &flow, &classification);
        
        // Test specific protocol detection
        traffic_classifier_is_tls_handshake(data, size);
        traffic_classifier_is_quic_packet(data, size);
        
        char sni[256];
        traffic_classifier_extract_sni(data, size, sni, sizeof(sni));
        
        traffic_classifier_destroy(classifier);
    }
    
    // Test privacy guards packet inspection
    privacy_guards_t *guards = privacy_guards_create();
    if (guards) {
        flow_tuple_t flow = {0};
        flow.ip_version = ip_version;
        
        if (size >= 20 && ip_version == 4) {
            memcpy(&flow.src_ip.v4.addr, &data[12], 4);
            memcpy(&flow.dst_ip.v4.addr, &data[16], 4);
            flow.protocol = data[9];
            
            if (flow.protocol == 6 && size >= 40) { // TCP
                flow.src_port = (data[20] << 8) | data[21];
                flow.dst_port = (data[22] << 8) | data[23];
            } else if (flow.protocol == 17 && size >= 28) { // UDP
                flow.src_port = (data[20] << 8) | data[21];
                flow.dst_port = (data[22] << 8) | data[23];
            }
        } else if (size >= 40 && ip_version == 6) {
            memcpy(flow.src_ip.v6.addr, &data[8], 16);
            memcpy(flow.dst_ip.v6.addr, &data[24], 16);
            flow.protocol = data[6];
            
            if (flow.protocol == 6 && size >= 60) { // TCP
                flow.src_port = (data[40] << 8) | data[41];
                flow.dst_port = (data[42] << 8) | data[43];
            } else if (flow.protocol == 17 && size >= 48) { // UDP
                flow.src_port = (data[40] << 8) | data[41];
                flow.dst_port = (data[42] << 8) | data[43];
            }
        }
        
        bool should_block = false;
        privacy_guards_inspect_packet(guards, data, size, &flow, &should_block);
        
        // Test TLS validation if it looks like TLS data
        if (size >= 5 && data[0] == 0x16) {
            privacy_guards_validate_tls_connection(guards, data, size);
        }
        
        privacy_guards_destroy(guards);
    }
    
    // Test hostname validation
    if (size > 0 && size < 254) {
        char hostname[256];
        size_t copy_size = size < 255 ? size : 255;
        memcpy(hostname, data, copy_size);
        hostname[copy_size] = '\0';
        
        // Ensure null termination for string operations
        for (size_t i = 0; i < copy_size; i++) {
            if (hostname[i] == '\0') break;
            if (hostname[i] < 32 || hostname[i] > 126) {
                hostname[i] = 'a'; // Replace invalid chars
            }
        }
        
        dns_is_valid_hostname(hostname);
    }
    
    return 0;
}

// Additional fuzzing entry points for specific components
extern "C" int LLVMFuzzerTestDNSPacket(const uint8_t *data, size_t size) {
    if (size < 12) return 0;
    
    dns_response_t response = {0};
    if (dns_parse_packet(data, size, &response)) {
        dns_response_destroy(&response);
    }
    
    return 0;
}

extern "C" int LLVMFuzzerTestTLSPacket(const uint8_t *data, size_t size) {
    if (size < 5) return 0;
    
    traffic_classifier_is_tls_handshake(data, size);
    traffic_classifier_get_tls_version(data, size);
    
    char sni[256];
    traffic_classifier_extract_sni(data, size, sni, sizeof(sni));
    
    privacy_guards_t *guards = privacy_guards_create();
    if (guards) {
        privacy_guards_validate_tls_connection(guards, data, size);
        privacy_guards_destroy(guards);
    }
    
    return 0;
}