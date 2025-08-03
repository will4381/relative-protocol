#include "classifier/tls_quic.h"
#include "core/logging.h"
#include <stdlib.h>
#include <string.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <time.h>

#define TLS_HANDSHAKE_TYPE 0x16
#define TLS_VERSION_10 0x0301
#define TLS_VERSION_11 0x0302
#define TLS_VERSION_12 0x0303
#define TLS_VERSION_13 0x0304

#define QUIC_LONG_HEADER_BIT 0x80
#define QUIC_VERSION_1 0x00000001

struct traffic_classifier {
    classification_callback_t callback;
    void *user_data;
};

traffic_classifier_t *traffic_classifier_create(void) {
    traffic_classifier_t *classifier = calloc(1, sizeof(traffic_classifier_t));
    if (!classifier) {
        LOG_ERROR("Failed to allocate traffic classifier");
        return NULL;
    }
    
    LOG_INFO("Traffic classifier created");
    return classifier;
}

void traffic_classifier_destroy(traffic_classifier_t *classifier) {
    if (!classifier) return;
    
    free(classifier);
    LOG_INFO("Traffic classifier destroyed");
}

bool traffic_classifier_analyze_packet(traffic_classifier_t *classifier, 
                                      const uint8_t *packet, size_t length,
                                      const flow_tuple_t *flow,
                                      traffic_classification_t *result) {
    if (!classifier || !packet || !flow || !result) return false;
    
    memset(result, 0, sizeof(traffic_classification_t));
    result->timestamp_ns = clock_gettime_nsec_np(CLOCK_MONOTONIC);
    result->type = TRAFFIC_TYPE_UNKNOWN;
    result->confidence = 0;
    
    if (flow->protocol == PROTO_TCP) {
        if (flow->dst_port == 80) {
            result->type = TRAFFIC_TYPE_HTTP;
            result->encrypted = false;
            result->confidence = 90;
            strncpy(result->application, "HTTP", sizeof(result->application) - 1);
            result->application[sizeof(result->application) - 1] = '\0';
        } else if (flow->dst_port == 443 || flow->dst_port == 8443) {
            if (traffic_classifier_is_tls_handshake(packet, length)) {
                uint16_t tls_version = traffic_classifier_get_tls_version(packet, length);
                result->tls_version = tls_version;
                result->encrypted = true;
                result->confidence = 95;
                
                if (tls_version == TLS_VERSION_13) {
                    result->type = TRAFFIC_TYPE_HTTPS_TLS13;
                } else {
                    result->type = TRAFFIC_TYPE_HTTPS_TLS12;
                }
                
                traffic_classifier_extract_sni(packet, length, result->server_name, sizeof(result->server_name));
                strncpy(result->application, "HTTPS", sizeof(result->application) - 1);
                result->application[sizeof(result->application) - 1] = '\0';
            }
        } else if (flow->dst_port == 22) {
            result->type = TRAFFIC_TYPE_SSH;
            result->encrypted = true;
            result->confidence = 85;
            strncpy(result->application, "SSH", sizeof(result->application) - 1);
            result->application[sizeof(result->application) - 1] = '\0';
        } else if (flow->dst_port == 21 || flow->dst_port == 20) {
            result->type = TRAFFIC_TYPE_FTP;
            result->encrypted = false;
            result->confidence = 80;
            strncpy(result->application, "FTP", sizeof(result->application) - 1);
            result->application[sizeof(result->application) - 1] = '\0';
        }
    } else if (flow->protocol == PROTO_UDP) {
        if (flow->dst_port == 53) {
            result->type = TRAFFIC_TYPE_DNS;
            result->encrypted = false;
            result->confidence = 95;
            strncpy(result->application, "DNS", sizeof(result->application) - 1);
            result->application[sizeof(result->application) - 1] = '\0';
        } else if (flow->dst_port == 443 || flow->dst_port == 8443) {
            if (traffic_classifier_is_quic_packet(packet, length)) {
                result->type = TRAFFIC_TYPE_QUIC;
                result->encrypted = true;
                result->confidence = 90;
                strncpy(result->application, "QUIC", sizeof(result->application) - 1);
                result->application[sizeof(result->application) - 1] = '\0';
            }
        }
    }
    
    traffic_classifier_detect_application(classifier, flow, packet, length, 
                                        result->application, sizeof(result->application));
    
    if (classifier->callback && result->type != TRAFFIC_TYPE_UNKNOWN) {
        classifier->callback(result, classifier->user_data);
    }
    
    return result->type != TRAFFIC_TYPE_UNKNOWN;
}

bool traffic_classifier_is_tls_handshake(const uint8_t *data, size_t length) {
    if (!data || length < 6) return false;
    
    return data[0] == TLS_HANDSHAKE_TYPE &&
           data[1] == 0x03 && 
           (data[2] >= 0x01 && data[2] <= 0x04);
}

bool traffic_classifier_is_quic_packet(const uint8_t *data, size_t length) {
    if (!data || length < 1) return false;
    
    return (data[0] & QUIC_LONG_HEADER_BIT) != 0;
}

bool traffic_classifier_extract_sni(const uint8_t *tls_data, size_t length, char *sni, size_t sni_size) {
    if (!tls_data || length < 43 || !sni || sni_size == 0) return false;
    
    const uint8_t *ptr = tls_data + 43;
    size_t remaining = length - 43;
    
    if (remaining < 2) return false;
    uint8_t session_id_len = *ptr++;
    remaining--;
    
    if (remaining < session_id_len) return false;
    ptr += session_id_len;
    remaining -= session_id_len;
    
    if (remaining < 2) return false;
    uint16_t cipher_suites_len = (ptr[0] << 8) | ptr[1];
    ptr += 2;
    remaining -= 2;
    
    if (remaining < cipher_suites_len) return false;
    ptr += cipher_suites_len;
    remaining -= cipher_suites_len;
    
    if (remaining < 1) return false;
    uint8_t compression_methods_len = *ptr++;
    remaining--;
    
    if (remaining < compression_methods_len) return false;
    ptr += compression_methods_len;
    remaining -= compression_methods_len;
    
    if (remaining < 2) return false;
    uint16_t extensions_len = (ptr[0] << 8) | ptr[1];
    ptr += 2;
    remaining -= 2;
    
    // Validate extensions length doesn't exceed remaining data
    if (extensions_len > remaining) return false;
    
    while (remaining >= 4) {
        uint16_t ext_type = (ptr[0] << 8) | ptr[1];
        uint16_t ext_len = (ptr[2] << 8) | ptr[3];
        ptr += 4;
        remaining -= 4;
        
        if (remaining < ext_len) break;
        
        if (ext_type == 0x0000) { // Server Name Indication
            if (ext_len >= 5) {
                const uint8_t *sni_ptr = ptr + 5;
                uint16_t sni_len = (ptr[3] << 8) | ptr[4];
                
                if (sni_len > 0 && sni_len < sni_size && ext_len >= 5 + sni_len) {
                    memcpy(sni, sni_ptr, sni_len);
                    sni[sni_len] = '\0';
                    return true;
                }
            }
            break;
        }
        
        ptr += ext_len;
        remaining -= ext_len;
    }
    
    return false;
}

uint16_t traffic_classifier_get_tls_version(const uint8_t *tls_data, size_t length) {
    if (!tls_data || length < 3) return 0;
    
    return (tls_data[1] << 8) | tls_data[2];
}

bool traffic_classifier_detect_application(traffic_classifier_t *classifier,
                                          const flow_tuple_t *flow,
                                          const uint8_t *payload, size_t payload_length,
                                          char *app_name, size_t app_name_size) {
    if (!classifier || !flow || !payload || !app_name || app_name_size == 0) return false;
    
    const char *patterns[] = {
        "YouTube", "TikTok", "Netflix", "Amazon", "Facebook", "Instagram", 
        "WhatsApp", "Telegram", "Discord", "Zoom", "Teams", "Slack"
    };
    
    for (size_t i = 0; i < sizeof(patterns) / sizeof(patterns[0]); i++) {
        if (payload_length >= strlen(patterns[i]) &&
            memmem(payload, payload_length, patterns[i], strlen(patterns[i]))) {
            strncpy(app_name, patterns[i], app_name_size - 1);
            app_name[app_name_size - 1] = '\0';
            return true;
        }
    }
    
    return false;
}

void traffic_classifier_set_callback(traffic_classifier_t *classifier, 
                                    classification_callback_t callback, void *user_data) {
    if (!classifier) return;
    
    classifier->callback = callback;
    classifier->user_data = user_data;
}

const char *traffic_type_string(traffic_type_t type) {
    switch (type) {
        case TRAFFIC_TYPE_UNKNOWN: return "Unknown";
        case TRAFFIC_TYPE_HTTP: return "HTTP";
        case TRAFFIC_TYPE_HTTPS_TLS12: return "HTTPS (TLS 1.2)";
        case TRAFFIC_TYPE_HTTPS_TLS13: return "HTTPS (TLS 1.3)";
        case TRAFFIC_TYPE_QUIC: return "QUIC";
        case TRAFFIC_TYPE_DNS: return "DNS";
        case TRAFFIC_TYPE_SSH: return "SSH";
        case TRAFFIC_TYPE_FTP: return "FTP";
        case TRAFFIC_TYPE_P2P: return "P2P";
        case TRAFFIC_TYPE_STREAMING: return "Streaming";
        case TRAFFIC_TYPE_GAMING: return "Gaming";
        case TRAFFIC_TYPE_VPN: return "VPN";
        default: return "Invalid";
    }
}