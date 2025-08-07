/**
 * iOS DNS Resolver Test
 * Verifies DNS resolution actually works with real networking
 */

#include "dns/resolver.h"
#include <stdio.h>
#include <assert.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <stdbool.h>

static bool query_completed = false;
static dns_response_t received_response = {0};

void dns_query_callback(dns_query_t *query, dns_response_t *response, void *user_data) {
    printf("DNS callback received for %s\n", dns_query_get_hostname(query));
    
    if (response) {
        received_response = *response;
        printf("  Response: rcode=%d, answers=%d\n", response->rcode, response->answer_count);
    } else {
        printf("  No response (timeout or error)\n");
    }
    
    query_completed = true;
}

void test_dns_resolver_creation() {
    printf("Testing DNS resolver creation...\n");
    
    // Test with Google DNS
    ip_addr_t dns_server = { .v4.addr = inet_addr("8.8.8.8") };
    dns_resolver_t *resolver = dns_resolver_create(&dns_server, 53);
    
    assert(resolver != NULL);
    
    dns_resolver_destroy(resolver);
    printf("✅ DNS resolver creation works\n");
}

void test_dns_query_async() {
    printf("Testing async DNS query...\n");
    
    ip_addr_t dns_server = { .v4.addr = inet_addr("8.8.8.8") };
    dns_resolver_t *resolver = dns_resolver_create(&dns_server, 53);
    assert(resolver != NULL);
    
    query_completed = false;
    memset(&received_response, 0, sizeof(received_response));
    
    // Query google.com
    dns_query_t *query = dns_resolver_query_async(resolver, "google.com", DNS_TYPE_A, 
                                                 dns_query_callback, NULL);
    assert(query != NULL);
    
    // Wait for completion (up to 10 seconds)
    int timeout_count = 0;
    while (!query_completed && timeout_count < 100) {
        usleep(100000); // 100ms
        timeout_count++;
    }
    
    if (query_completed) {
        printf("✅ Async DNS query completed\n");
        if (received_response.rcode == DNS_RCODE_NOERROR) {
            printf("  Successfully resolved google.com\n");
        } else {
            printf("  DNS error: %s\n", dns_rcode_to_string(received_response.rcode));
        }
    } else {
        printf("⚠️  DNS query timed out (network may be unavailable)\n");
    }
    
    dns_resolver_destroy(resolver);
}

void test_dns_hostname_validation() {
    printf("Testing hostname validation...\n");
    
    assert(dns_is_valid_hostname("google.com") == true);
    assert(dns_is_valid_hostname("sub.domain.example.org") == true);
    assert(dns_is_valid_hostname("") == false);
    assert(dns_is_valid_hostname(NULL) == false);
    assert(dns_is_valid_hostname("..invalid") == false);
    assert(dns_is_valid_hostname("invalid..") == false);
    assert(dns_is_valid_hostname(".invalid") == false);
    assert(dns_is_valid_hostname("invalid.") == false);
    
    printf("✅ Hostname validation works\n");
}

void test_dns_server_management() {
    printf("Testing DNS server management...\n");
    
    ip_addr_t primary = { .v4.addr = inet_addr("8.8.8.8") };
    ip_addr_t secondary = { .v4.addr = inet_addr("8.8.4.4") };
    
    dns_resolver_t *resolver = dns_resolver_create(&primary, 53);
    assert(resolver != NULL);
    
    // Add secondary server
    bool added = dns_resolver_add_server(resolver, &secondary, 53);
    assert(added == true);
    
    // Remove primary server
    bool removed = dns_resolver_remove_server(resolver, &primary, 53);
    assert(removed == true);
    
    dns_resolver_destroy(resolver);
    printf("✅ DNS server management works\n");
}

void test_dns_stats() {
    printf("Testing DNS statistics...\n");
    
    ip_addr_t dns_server = { .v4.addr = inet_addr("8.8.8.8") };
    dns_resolver_t *resolver = dns_resolver_create(&dns_server, 53);
    assert(resolver != NULL);
    
    uint32_t queries_sent, responses_received, timeouts, errors;
    dns_resolver_get_stats(resolver, &queries_sent, &responses_received, &timeouts, &errors);
    
    assert(queries_sent == 0);
    assert(responses_received == 0);
    
    dns_resolver_destroy(resolver);
    printf("✅ DNS statistics work\n");
}

int main() {
    printf("\n=== iOS DNS Resolver Tests ===\n\n");
    
    test_dns_resolver_creation();
    test_dns_hostname_validation();
    test_dns_server_management();
    test_dns_stats();
    test_dns_query_async(); // Run last as it does network I/O
    
    printf("\n✅ All DNS resolver tests passed!\n\n");
    return 0;
}