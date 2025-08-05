#ifndef RELATIVE_VPN_TLS_QUIC_CLASSIFIER_H
#define RELATIVE_VPN_TLS_QUIC_CLASSIFIER_H

#include "core/types.h"
#include <stdint.h>
#include <stdbool.h>

typedef struct traffic_classifier traffic_classifier_t;

typedef enum traffic_type {
    TRAFFIC_TYPE_UNKNOWN = 0,
    TRAFFIC_TYPE_HTTP,
    TRAFFIC_TYPE_HTTPS_TLS12,
    TRAFFIC_TYPE_HTTPS_TLS13,
    TRAFFIC_TYPE_QUIC,
    TRAFFIC_TYPE_DNS,
    TRAFFIC_TYPE_SSH,
    TRAFFIC_TYPE_FTP,
    TRAFFIC_TYPE_P2P,
    TRAFFIC_TYPE_STREAMING,
    TRAFFIC_TYPE_GAMING,
    TRAFFIC_TYPE_VPN
} traffic_type_t;

typedef struct traffic_classification {
    traffic_type_t type;
    char server_name[256];
    char application[64];
    uint16_t tls_version;
    bool encrypted;
    uint8_t confidence;
    uint64_t timestamp_ns;
} traffic_classification_t;

typedef void (*classification_callback_t)(const traffic_classification_t *classification, void *user_data);

traffic_classifier_t *traffic_classifier_create(void);
void traffic_classifier_destroy(traffic_classifier_t *classifier);

bool traffic_classifier_analyze_packet(traffic_classifier_t *classifier, 
                                      const uint8_t *packet, size_t length,
                                      const flow_tuple_t *flow,
                                      traffic_classification_t *result);

bool traffic_classifier_is_tls_handshake(const uint8_t *data, size_t length);
bool traffic_classifier_is_quic_packet(const uint8_t *data, size_t length);
bool traffic_classifier_extract_sni(const uint8_t *tls_data, size_t length, char *sni, size_t sni_size);

void traffic_classifier_set_callback(traffic_classifier_t *classifier, 
                                    classification_callback_t callback, void *user_data);

uint16_t traffic_classifier_get_tls_version(const uint8_t *tls_data, size_t length);
bool traffic_classifier_detect_application(traffic_classifier_t *classifier,
                                          const flow_tuple_t *flow,
                                          const uint8_t *payload, size_t payload_length,
                                          char *app_name, size_t app_name_size);

const char *traffic_type_string(traffic_type_t type);

#endif