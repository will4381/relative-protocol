#include <gtest/gtest.h>
#include "metrics/ring_buffer.h"
#include <thread>
#include <vector>
#include <atomic>

class RingBufferTest : public ::testing::Test {
protected:
    void SetUp() override {
        buffer = ring_buffer_create(8);
        ASSERT_NE(buffer, nullptr);
    }
    
    void TearDown() override {
        if (buffer) {
            ring_buffer_destroy(buffer);
        }
    }
    
    ring_buffer_t *buffer;
};

TEST_F(RingBufferTest, BasicOperations) {
    EXPECT_EQ(ring_buffer_capacity(buffer), 8);
    EXPECT_EQ(ring_buffer_size(buffer), 0);
    EXPECT_TRUE(ring_buffer_is_empty(buffer));
    EXPECT_FALSE(ring_buffer_is_full(buffer));
    
    flow_metrics_t metrics = {};
    metrics.src_port = 80;
    metrics.dst_port = 8080;
    metrics.protocol = 6;
    metrics.bytes_in = 1024;
    
    EXPECT_TRUE(ring_buffer_push(buffer, &metrics));
    EXPECT_EQ(ring_buffer_size(buffer), 1);
    EXPECT_FALSE(ring_buffer_is_empty(buffer));
    EXPECT_FALSE(ring_buffer_is_full(buffer));
    
    flow_metrics_t retrieved = {};
    EXPECT_TRUE(ring_buffer_pop(buffer, &retrieved));
    EXPECT_EQ(ring_buffer_size(buffer), 0);
    EXPECT_TRUE(ring_buffer_is_empty(buffer));
    
    EXPECT_EQ(retrieved.src_port, 80);
    EXPECT_EQ(retrieved.dst_port, 8080);
    EXPECT_EQ(retrieved.protocol, 6);
    EXPECT_EQ(retrieved.bytes_in, 1024);
}

TEST_F(RingBufferTest, FillAndEmpty) {
    flow_metrics_t metrics = {};
    
    for (size_t i = 0; i < ring_buffer_capacity(buffer); ++i) {
        metrics.src_port = static_cast<uint16_t>(i);
        EXPECT_TRUE(ring_buffer_push(buffer, &metrics));
    }
    
    EXPECT_TRUE(ring_buffer_is_full(buffer));
    EXPECT_EQ(ring_buffer_size(buffer), ring_buffer_capacity(buffer));
    
    EXPECT_FALSE(ring_buffer_push(buffer, &metrics));
    
    for (size_t i = 0; i < ring_buffer_capacity(buffer); ++i) {
        flow_metrics_t retrieved = {};
        EXPECT_TRUE(ring_buffer_pop(buffer, &retrieved));
        EXPECT_EQ(retrieved.src_port, i);
    }
    
    EXPECT_TRUE(ring_buffer_is_empty(buffer));
    
    flow_metrics_t dummy = {};
    EXPECT_FALSE(ring_buffer_pop(buffer, &dummy));
}

TEST_F(RingBufferTest, WrapAround) {
    flow_metrics_t metrics = {};
    
    for (size_t i = 0; i < ring_buffer_capacity(buffer); ++i) {
        metrics.src_port = static_cast<uint16_t>(i);
        EXPECT_TRUE(ring_buffer_push(buffer, &metrics));
    }
    
    for (size_t i = 0; i < 4; ++i) {
        flow_metrics_t retrieved = {};
        EXPECT_TRUE(ring_buffer_pop(buffer, &retrieved));
        EXPECT_EQ(retrieved.src_port, i);
    }
    
    for (size_t i = 100; i < 104; ++i) {
        metrics.src_port = static_cast<uint16_t>(i);
        EXPECT_TRUE(ring_buffer_push(buffer, &metrics));
    }
    
    for (size_t i = 4; i < 8; ++i) {
        flow_metrics_t retrieved = {};
        EXPECT_TRUE(ring_buffer_pop(buffer, &retrieved));
        EXPECT_EQ(retrieved.src_port, i);
    }
    
    for (size_t i = 100; i < 104; ++i) {
        flow_metrics_t retrieved = {};
        EXPECT_TRUE(ring_buffer_pop(buffer, &retrieved));
        EXPECT_EQ(retrieved.src_port, i);
    }
}

TEST_F(RingBufferTest, Clear) {
    flow_metrics_t metrics = {};
    
    for (size_t i = 0; i < 5; ++i) {
        metrics.src_port = static_cast<uint16_t>(i);
        EXPECT_TRUE(ring_buffer_push(buffer, &metrics));
    }
    
    EXPECT_EQ(ring_buffer_size(buffer), 5);
    
    ring_buffer_clear(buffer);
    
    EXPECT_EQ(ring_buffer_size(buffer), 0);
    EXPECT_TRUE(ring_buffer_is_empty(buffer));
    EXPECT_FALSE(ring_buffer_is_full(buffer));
}

TEST_F(RingBufferTest, ConcurrentAccess) {
    const size_t num_producers = 4;
    const size_t num_consumers = 2;
    const size_t items_per_producer = 1000;
    
    std::atomic<size_t> total_produced{0};
    std::atomic<size_t> total_consumed{0};
    std::atomic<bool> stop_consumers{false};
    
    std::vector<std::thread> producers;
    std::vector<std::thread> consumers;
    
    for (size_t p = 0; p < num_producers; ++p) {
        producers.emplace_back([&, p]() {
            for (size_t i = 0; i < items_per_producer; ++i) {
                flow_metrics_t metrics = {};
                metrics.src_port = static_cast<uint16_t>(p * items_per_producer + i);
                
                while (!ring_buffer_push(buffer, &metrics)) {
                    std::this_thread::yield();
                }
                
                total_produced.fetch_add(1);
            }
        });
    }
    
    for (size_t c = 0; c < num_consumers; ++c) {
        consumers.emplace_back([&]() {
            while (!stop_consumers.load()) {
                flow_metrics_t metrics = {};
                if (ring_buffer_pop(buffer, &metrics)) {
                    total_consumed.fetch_add(1);
                } else {
                    std::this_thread::yield();
                }
            }
        });
    }
    
    for (auto& producer : producers) {
        producer.join();
    }
    
    while (total_consumed.load() < total_produced.load()) {
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }
    
    stop_consumers.store(true);
    
    for (auto& consumer : consumers) {
        consumer.join();
    }
    
    EXPECT_EQ(total_produced.load(), num_producers * items_per_producer);
    EXPECT_EQ(total_consumed.load(), num_producers * items_per_producer);
}

TEST_F(RingBufferTest, InvalidInputs) {
    EXPECT_EQ(ring_buffer_create(0), nullptr);
    EXPECT_EQ(ring_buffer_create(SIZE_MAX), nullptr);
    
    EXPECT_EQ(ring_buffer_size(nullptr), 0);
    EXPECT_EQ(ring_buffer_capacity(nullptr), 0);
    EXPECT_TRUE(ring_buffer_is_empty(nullptr));
    EXPECT_FALSE(ring_buffer_is_full(nullptr));
    
    flow_metrics_t metrics = {};
    EXPECT_FALSE(ring_buffer_push(nullptr, &metrics));
    EXPECT_FALSE(ring_buffer_push(buffer, nullptr));
    
    EXPECT_FALSE(ring_buffer_pop(nullptr, &metrics));
    EXPECT_FALSE(ring_buffer_pop(buffer, nullptr));
    
    ring_buffer_clear(nullptr);
    ring_buffer_destroy(nullptr);
}