#ifndef RELATIVE_VPN_DNS_RESOLVER_H
#define RELATIVE_VPN_DNS_RESOLVER_H

#include "core/types.h"
#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

#define DNS_MAX_NAME_LENGTH 253
#define DNS_MAX_LABEL_LENGTH 63
#define DNS_DEFAULT_TIMEOUT_MS 5000

typedef struct dns_resolver dns_resolver_t;
typedef struct dns_query dns_query_t;

typedef enum dns_record_type {
    DNS_TYPE_A = 1,
    DNS_TYPE_AAAA = 28,
    DNS_TYPE_CNAME = 5,
    DNS_TYPE_MX = 15,
    DNS_TYPE_TXT = 16,
    DNS_TYPE_PTR = 12
} dns_record_type_t;

typedef enum dns_response_code {
    DNS_RCODE_NOERROR = 0,
    DNS_RCODE_FORMERR = 1,
    DNS_RCODE_SERVFAIL = 2,
    DNS_RCODE_NXDOMAIN = 3,
    DNS_RCODE_NOTIMP = 4,
    DNS_RCODE_REFUSED = 5
} dns_response_code_t;

typedef struct dns_record {
    char name[DNS_MAX_NAME_LENGTH + 1];
    dns_record_type_t type;
    uint16_t record_class;
    uint32_t ttl;
    uint16_t data_length;
    union {
        uint32_t ipv4_addr;
        uint8_t ipv6_addr[16];
        char cname[DNS_MAX_NAME_LENGTH + 1];
        uint8_t *raw_data;
    } data;
} dns_record_t;

typedef struct dns_response {
    uint16_t transaction_id;
    dns_response_code_t rcode;
    bool authoritative;
    bool truncated;
    bool recursion_available;
    uint16_t question_count;
    uint16_t answer_count;
    uint16_t authority_count;
    uint16_t additional_count;
    dns_record_t *answers;
    uint64_t timestamp_ns;
} dns_response_t;

typedef void (*dns_query_callback_t)(dns_query_t *query, dns_response_t *response, void *user_data);

dns_resolver_t *dns_resolver_create(const ip_addr_t *server_addr, uint16_t server_port);
void dns_resolver_destroy(dns_resolver_t *resolver);

bool dns_resolver_add_server(dns_resolver_t *resolver, const ip_addr_t *server_addr, uint16_t server_port);
bool dns_resolver_remove_server(dns_resolver_t *resolver, const ip_addr_t *server_addr, uint16_t server_port);

dns_query_t *dns_resolver_query_async(dns_resolver_t *resolver, const char *hostname, 
                                     dns_record_type_t type, dns_query_callback_t callback, void *user_data);
bool dns_resolver_query_sync(dns_resolver_t *resolver, const char *hostname, 
                            dns_record_type_t type, dns_response_t *response, uint32_t timeout_ms);

void dns_query_cancel(dns_query_t *query);
bool dns_query_is_completed(dns_query_t *query);
const char *dns_query_get_hostname(dns_query_t *query);
dns_record_type_t dns_query_get_type(dns_query_t *query);

void dns_response_destroy(dns_response_t *response);

bool dns_resolver_process_packet(dns_resolver_t *resolver, const uint8_t *packet, size_t length, 
                                const ip_addr_t *src_addr, uint16_t src_port);
void dns_resolver_process_timeouts(dns_resolver_t *resolver);

void dns_resolver_set_timeout(dns_resolver_t *resolver, uint32_t timeout_ms);
void dns_resolver_enable_dnssec(dns_resolver_t *resolver, bool enable);
void dns_resolver_set_max_retries(dns_resolver_t *resolver, uint8_t max_retries);

size_t dns_resolver_get_query_count(dns_resolver_t *resolver);
void dns_resolver_get_stats(dns_resolver_t *resolver, uint32_t *queries_sent, uint32_t *responses_received, 
                           uint32_t *timeouts, uint32_t *errors);

bool dns_is_valid_hostname(const char *hostname);
bool dns_parse_packet(const uint8_t *packet, size_t length, dns_response_t *response);
size_t dns_build_query(const char *hostname, dns_record_type_t type, uint16_t transaction_id, 
                      uint8_t *buffer, size_t buffer_size);

const char *dns_rcode_to_string(dns_response_code_t rcode);
const char *dns_type_to_string(dns_record_type_t type);

#ifdef __cplusplus
}
#endif

#endif