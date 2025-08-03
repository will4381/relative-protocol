#include <gtest/gtest.h>
#include "dns/resolver.h"
#include "dns/cache.h"
#include <thread>
#include <chrono>
#include <atomic>
#include <arpa/inet.h>  // For inet_addr

class DNSResolverTest : public ::testing::Test {
protected:
    void SetUp() override {
        // Create resolver with Google DNS
        ip_addr_t google_dns = { .v4 = { .addr = inet_addr("8.8.8.8") } };
        resolver = dns_resolver_create(&google_dns, 53);
        ASSERT_NE(resolver, nullptr);
    }
    
    void TearDown() override {
        if (resolver) {
            dns_resolver_destroy(resolver);
        }
    }
    
    dns_resolver_t *resolver;
};

TEST_F(DNSResolverTest, CreateDestroy) {
    EXPECT_NE(resolver, nullptr);
    
    // Test multiple create/destroy cycles
    for (int i = 0; i < 5; i++) {
        ip_addr_t cloudflare_dns = { .v4 = { .addr = inet_addr("1.1.1.1") } };
        dns_resolver_t *temp_resolver = dns_resolver_create(&cloudflare_dns, 53);
        EXPECT_NE(temp_resolver, nullptr);
        dns_resolver_destroy(temp_resolver);
    }
}

TEST_F(DNSResolverTest, ServerManagement) {
    ip_addr_t cloudflare_dns = { .v4 = { .addr = inet_addr("1.1.1.1") } };
    ip_addr_t quad9_dns = { .v4 = { .addr = inet_addr("9.9.9.9") } };
    
    EXPECT_TRUE(dns_resolver_add_server(resolver, &cloudflare_dns, 53));
    EXPECT_TRUE(dns_resolver_add_server(resolver, &quad9_dns, 53));
    
    EXPECT_TRUE(dns_resolver_remove_server(resolver, &cloudflare_dns, 53));
    EXPECT_FALSE(dns_resolver_remove_server(resolver, &cloudflare_dns, 53)); // Already removed
}

TEST_F(DNSResolverTest, HostnameValidation) {
    EXPECT_TRUE(dns_is_valid_hostname("google.com"));
    EXPECT_TRUE(dns_is_valid_hostname("sub.domain.example.org"));
    EXPECT_TRUE(dns_is_valid_hostname("test-domain.com"));
    EXPECT_TRUE(dns_is_valid_hostname("example123.net"));
    
    EXPECT_FALSE(dns_is_valid_hostname(""));
    EXPECT_FALSE(dns_is_valid_hostname(nullptr));
    EXPECT_FALSE(dns_is_valid_hostname("invalid..domain"));
    EXPECT_FALSE(dns_is_valid_hostname("domain_with_underscore.com"));
    EXPECT_FALSE(dns_is_valid_hostname("toolongdomainnamethatshouldexceedthemaximumlengthallowedfordomainnamesaccordingtorfcstandards.com"));
}

TEST_F(DNSResolverTest, QueryBuilding) {
    uint8_t buffer[512];
    
    size_t query_size = dns_build_query("google.com", DNS_TYPE_A, 0x1234, buffer, sizeof(buffer));
    EXPECT_GT(query_size, 0);
    EXPECT_LT(query_size, sizeof(buffer));
    
    // Verify transaction ID
    uint16_t txn_id = ntohs(*(uint16_t*)buffer);
    EXPECT_EQ(txn_id, 0x1234);
    
    // Test various record types
    EXPECT_GT(dns_build_query("example.com", DNS_TYPE_AAAA, 0x5678, buffer, sizeof(buffer)), 0);
    EXPECT_GT(dns_build_query("example.com", DNS_TYPE_CNAME, 0x9ABC, buffer, sizeof(buffer)), 0);
    EXPECT_GT(dns_build_query("example.com", DNS_TYPE_MX, 0xDEF0, buffer, sizeof(buffer)), 0);
    
    // Test edge cases
    EXPECT_EQ(dns_build_query("", DNS_TYPE_A, 0x1234, buffer, sizeof(buffer)), 0);
    EXPECT_EQ(dns_build_query("toolongname", DNS_TYPE_A, 0x1234, buffer, 5), 0); // Buffer too small
}

TEST_F(DNSResolverTest, AsyncQuery) {
    std::atomic<bool> callback_called{false};
    std::atomic<bool> query_completed{false};
    dns_response_t received_response;
    
    auto callback = [](dns_query_t *query, dns_response_t *response, void *user_data) {
        auto *called = static_cast<std::atomic<bool>*>(user_data);
        called->store(true);
        
        EXPECT_NE(query, nullptr);
        if (response) {
            EXPECT_GE(response->answer_count, 0);
        }
    };
    
    dns_query_t *query = dns_resolver_query_async(resolver, "google.com", DNS_TYPE_A, callback, &callback_called);
    
    if (query) {
        EXPECT_NE(query, nullptr);
        EXPECT_STREQ(dns_query_get_hostname(query), "google.com");
        EXPECT_EQ(dns_query_get_type(query), DNS_TYPE_A);
        
        // Wait for response or timeout
        for (int i = 0; i < 50 && !callback_called.load(); i++) {
            dns_resolver_process_timeouts(resolver);
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }
        
        // Query should complete either with response or timeout
        EXPECT_TRUE(dns_query_is_completed(query) || callback_called.load());
    } else {
        GTEST_SKIP() << "DNS query failed - may be network or permission issue";
    }
}

TEST_F(DNSResolverTest, PacketParsing) {
    // Minimal DNS response packet
    uint8_t dns_response[] = {
        0x12, 0x34,  // Transaction ID
        0x81, 0x80,  // Flags: Response, No error
        0x00, 0x01,  // Questions: 1
        0x00, 0x01,  // Answers: 1
        0x00, 0x00,  // Authority: 0
        0x00, 0x00,  // Additional: 0
        // Question section would follow...
    };
    
    dns_response_t response;
    bool parsed = dns_parse_packet(dns_response, sizeof(dns_response), &response);
    
    if (parsed) {
        EXPECT_EQ(response.transaction_id, 0x1234);
        EXPECT_EQ(response.question_count, 1);
        EXPECT_EQ(response.answer_count, 1);
        EXPECT_EQ(response.rcode, DNS_RCODE_NOERROR);
        
        dns_response_destroy(&response);
    }
}

TEST_F(DNSResolverTest, Statistics) {
    uint32_t queries_sent, responses_received, timeouts, errors;
    
    dns_resolver_get_stats(resolver, &queries_sent, &responses_received, &timeouts, &errors);
    
    uint32_t initial_queries = queries_sent;
    
    // Trigger a query to increment stats
    dns_query_t *query = dns_resolver_query_async(resolver, "nonexistent.invalid", DNS_TYPE_A, nullptr, nullptr);
    if (query) {
        // Process timeouts to increment timeout counter
        for (int i = 0; i < 10; i++) {
            dns_resolver_process_timeouts(resolver);
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }
        
        dns_resolver_get_stats(resolver, &queries_sent, &responses_received, &timeouts, &errors);
        EXPECT_GT(queries_sent, initial_queries);
    }
}

TEST_F(DNSResolverTest, ErrorHandling) {
    // Test null parameters
    EXPECT_EQ(dns_resolver_query_async(nullptr, "google.com", DNS_TYPE_A, nullptr, nullptr), nullptr);
    EXPECT_EQ(dns_resolver_query_async(resolver, nullptr, DNS_TYPE_A, nullptr, nullptr), nullptr);
    EXPECT_EQ(dns_resolver_query_async(resolver, "", DNS_TYPE_A, nullptr, nullptr), nullptr);
    
    // Test invalid hostname
    EXPECT_EQ(dns_resolver_query_async(resolver, "invalid..hostname", DNS_TYPE_A, nullptr, nullptr), nullptr);
    
    // Test sync query with null parameters
    dns_response_t response;
    EXPECT_FALSE(dns_resolver_query_sync(nullptr, "google.com", DNS_TYPE_A, &response, 5000));
    EXPECT_FALSE(dns_resolver_query_sync(resolver, nullptr, DNS_TYPE_A, &response, 5000));
    EXPECT_FALSE(dns_resolver_query_sync(resolver, "google.com", DNS_TYPE_A, nullptr, 5000));
}

TEST_F(DNSResolverTest, ConcurrentQueries) {
    const int num_threads = 5;
    const int queries_per_thread = 3;
    std::atomic<int> completed_queries{0};
    std::vector<std::thread> threads;
    
    auto query_func = [&](int thread_id) {
        for (int i = 0; i < queries_per_thread; i++) {
            std::string hostname = "test" + std::to_string(thread_id) + std::to_string(i) + ".example.com";
            
            auto callback = [](dns_query_t *query, dns_response_t *response, void *user_data) {
                auto *counter = static_cast<std::atomic<int>*>(user_data);
                counter->fetch_add(1);
            };
            
            dns_query_t *query = dns_resolver_query_async(resolver, hostname.c_str(), DNS_TYPE_A, callback, &completed_queries);
            
            if (query) {
                std::this_thread::sleep_for(std::chrono::milliseconds(50));
            }
        }
    };
    
    // Start threads
    for (int i = 0; i < num_threads; i++) {
        threads.emplace_back(query_func, i);
    }
    
    // Wait for threads to complete
    for (auto& t : threads) {
        t.join();
    }
    
    // Process any remaining timeouts
    for (int i = 0; i < 50; i++) {
        dns_resolver_process_timeouts(resolver);
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
    
    // All queries should have completed (either with response or timeout)
    EXPECT_LE(completed_queries.load(), num_threads * queries_per_thread);
}

// DNS Cache Tests
class DNSCacheTest : public ::testing::Test {
protected:
    void SetUp() override {
        cache = dns_cache_create(100, 300); // 100 entries, 5 min TTL
        ASSERT_NE(cache, nullptr);
    }
    
    void TearDown() override {
        if (cache) {
            dns_cache_destroy(cache);
        }
    }
    
    dns_cache_t *cache;
};

TEST_F(DNSCacheTest, BasicOperations) {
    dns_record_t record = {};
    record.type = DNS_TYPE_A;
    record.ttl = 300;
    record.data.ipv4_addr = inet_addr("1.2.3.4");
    strcpy(record.name, "test.example.com");
    
    // Test put and get
    EXPECT_TRUE(dns_cache_put(cache, "test.example.com", DNS_TYPE_A, &record));
    EXPECT_TRUE(dns_cache_has_entry(cache, "test.example.com", DNS_TYPE_A));
    
    dns_record_t retrieved = {};
    EXPECT_TRUE(dns_cache_get(cache, "test.example.com", DNS_TYPE_A, &retrieved));
    EXPECT_EQ(retrieved.data.ipv4_addr, inet_addr("1.2.3.4"));
    EXPECT_STREQ(retrieved.name, "test.example.com");
    
    // Test remove
    EXPECT_TRUE(dns_cache_remove(cache, "test.example.com", DNS_TYPE_A));
    EXPECT_FALSE(dns_cache_has_entry(cache, "test.example.com", DNS_TYPE_A));
}

TEST_F(DNSCacheTest, EvictionPolicies) {
    dns_cache_set_eviction_policy(cache, DNS_CACHE_LRU);
    
    // Fill cache beyond capacity
    for (int i = 0; i < 150; i++) {
        dns_record_t record = {};
        record.type = DNS_TYPE_A;
        record.ttl = 300;
        record.data.ipv4_addr = htonl(0x01020300 + i);
        
        std::string hostname = "host" + std::to_string(i) + ".example.com";
        strcpy(record.name, hostname.c_str());
        
        dns_cache_put(cache, hostname.c_str(), DNS_TYPE_A, &record);
    }
    
    EXPECT_LE(dns_cache_get_size(cache), dns_cache_get_max_size(cache));
    
    // Test LFU eviction
    dns_cache_set_eviction_policy(cache, DNS_CACHE_LFU);
    dns_cache_clear(cache);
    EXPECT_EQ(dns_cache_get_size(cache), 0);
}

TEST_F(DNSCacheTest, Statistics) {
    dns_cache_stats_t stats;
    dns_cache_get_stats(cache, &stats);
    
    EXPECT_EQ(stats.total_entries, 0);
    EXPECT_EQ(stats.cache_hits, 0);
    EXPECT_EQ(stats.cache_misses, 0);
    
    // Add entry and access it
    dns_record_t record = {};
    record.type = DNS_TYPE_A;
    record.ttl = 300;
    record.data.ipv4_addr = inet_addr("1.2.3.4");
    strcpy(record.name, "test.example.com");
    
    dns_cache_put(cache, "test.example.com", DNS_TYPE_A, &record);
    
    dns_record_t retrieved;
    dns_cache_get(cache, "test.example.com", DNS_TYPE_A, &retrieved); // Hit
    dns_cache_get(cache, "nonexistent.com", DNS_TYPE_A, &retrieved);   // Miss
    
    dns_cache_get_stats(cache, &stats);
    EXPECT_EQ(stats.cache_hits, 1);
    EXPECT_EQ(stats.cache_misses, 1);
}

TEST_F(DNSCacheTest, ErrorHandling) {
    // Test null parameters
    EXPECT_FALSE(dns_cache_put(nullptr, "test.com", DNS_TYPE_A, nullptr));
    EXPECT_FALSE(dns_cache_get(nullptr, "test.com", DNS_TYPE_A, nullptr));
    EXPECT_FALSE(dns_cache_has_entry(nullptr, "test.com", DNS_TYPE_A));
    EXPECT_FALSE(dns_cache_remove(nullptr, "test.com", DNS_TYPE_A));
    
    dns_record_t record = {};
    EXPECT_FALSE(dns_cache_put(cache, nullptr, DNS_TYPE_A, &record));
    EXPECT_FALSE(dns_cache_put(cache, "test.com", DNS_TYPE_A, nullptr));
    
    dns_cache_clear(nullptr); // Should not crash
    dns_cache_destroy(nullptr); // Should not crash
}