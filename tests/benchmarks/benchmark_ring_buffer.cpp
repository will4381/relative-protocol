#include <benchmark/benchmark.h>
#include "metrics/ring_buffer.h"
#include <random>
#include <vector>
#include <thread>

class RingBufferFixture : public benchmark::Fixture {
public:
    void SetUp(const ::benchmark::State& state) override {
        buffer = ring_buffer_create(state.range(0));
    }
    
    void TearDown(const ::benchmark::State& state) override {
        ring_buffer_destroy(buffer);
    }
    
    ring_buffer_t *buffer;
};

BENCHMARK_DEFINE_F(RingBufferFixture, SingleThreadedWrite)(benchmark::State& state) {
    vpn_metrics_t metrics = {};
    metrics.timestamp_ns = 1234567890;
    metrics.total_packets_processed = 1000;
    metrics.bytes_received = 1500000;
    metrics.bytes_sent = 1200000;
    
    for (auto _ : state) {
        ring_buffer_write(buffer, &metrics, sizeof(metrics));
        metrics.total_packets_processed++;
    }
    
    state.SetItemsProcessed(state.iterations());
    state.SetBytesProcessed(state.iterations() * sizeof(metrics));
}

BENCHMARK_REGISTER_F(RingBufferFixture, SingleThreadedWrite)
    ->Arg(1000)->Arg(10000)->Arg(100000)->Arg(1000000)
    ->Unit(benchmark::kMicrosecond);

BENCHMARK_DEFINE_F(RingBufferFixture, SingleThreadedRead)(benchmark::State& state) {
    // Pre-fill buffer
    vpn_metrics_t write_metrics = {};
    for (int i = 0; i < state.range(0) / 2; i++) {
        write_metrics.total_packets_processed = i;
        ring_buffer_write(buffer, &write_metrics, sizeof(write_metrics));
    }
    
    vpn_metrics_t read_metrics;
    for (auto _ : state) {
        if (!ring_buffer_read(buffer, &read_metrics, sizeof(read_metrics))) {
            // Buffer empty, refill it
            write_metrics.total_packets_processed++;
            ring_buffer_write(buffer, &write_metrics, sizeof(write_metrics));
            ring_buffer_read(buffer, &read_metrics, sizeof(read_metrics));
        }
    }
    
    state.SetItemsProcessed(state.iterations());
    state.SetBytesProcessed(state.iterations() * sizeof(read_metrics));
}

BENCHMARK_REGISTER_F(RingBufferFixture, SingleThreadedRead)
    ->Arg(1000)->Arg(10000)->Arg(100000)->Arg(1000000)
    ->Unit(benchmark::kMicrosecond);

BENCHMARK_DEFINE_F(RingBufferFixture, ConcurrentWriteRead)(benchmark::State& state) {
    const int num_threads = state.range(1);
    std::atomic<bool> start_flag{false};
    std::atomic<int> operations_completed{0};
    
    auto worker = [&](int thread_id, bool is_writer) {
        vpn_metrics_t metrics = {};
        metrics.timestamp_ns = clock_gettime_nsec_np(CLOCK_MONOTONIC);
        metrics.total_packets_processed = thread_id * 1000;
        
        // Wait for start signal
        while (!start_flag.load()) {
            std::this_thread::yield();
        }
        
        if (is_writer) {
            for (int i = 0; i < 1000; i++) {
                metrics.total_packets_processed = thread_id * 1000 + i;
                ring_buffer_write(buffer, &metrics, sizeof(metrics));
            }
        } else {
            vpn_metrics_t read_metrics;
            for (int i = 0; i < 1000; i++) {
                ring_buffer_read(buffer, &read_metrics, sizeof(read_metrics));
            }
        }
        
        operations_completed.fetch_add(1);
    };
    
    for (auto _ : state) {
        operations_completed.store(0);
        start_flag.store(false);
        
        std::vector<std::thread> threads;
        
        // Create writer and reader threads
        for (int i = 0; i < num_threads / 2; i++) {
            threads.emplace_back(worker, i, true);  // Writer
            threads.emplace_back(worker, i + num_threads/2, false); // Reader
        }
        
        auto start_time = std::chrono::high_resolution_clock::now();
        start_flag.store(true);
        
        for (auto& t : threads) {
            t.join();
        }
        
        auto end_time = std::chrono::high_resolution_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::nanoseconds>(end_time - start_time);
        state.SetIterationTime(duration.count() / 1e9);
    }
    
    state.SetItemsProcessed(state.iterations() * num_threads * 1000);
    state.UseManualTime();
}

BENCHMARK_REGISTER_F(RingBufferFixture, ConcurrentWriteRead)
    ->Args({100000, 2})->Args({100000, 4})->Args({100000, 8})
    ->Unit(benchmark::kMicrosecond);

// Standalone benchmarks
static void BM_RingBufferCreateDestroy(benchmark::State& state) {
    for (auto _ : state) {
        ring_buffer_t* buffer = ring_buffer_create(state.range(0));
        benchmark::DoNotOptimize(buffer);
        ring_buffer_destroy(buffer);
    }
    
    state.SetItemsProcessed(state.iterations());
}

BENCHMARK(BM_RingBufferCreateDestroy)
    ->Arg(1000)->Arg(10000)->Arg(100000)->Arg(1000000)
    ->Unit(benchmark::kMicrosecond);

static void BM_RingBufferBulkOperations(benchmark::State& state) {
    ring_buffer_t* buffer = ring_buffer_create(state.range(0));
    const int bulk_size = 100;
    
    std::vector<vpn_metrics_t> metrics_batch(bulk_size);
    for (int i = 0; i < bulk_size; i++) {
        metrics_batch[i].timestamp_ns = clock_gettime_nsec_np(CLOCK_MONOTONIC);
        metrics_batch[i].total_packets_processed = i;
    }
    
    for (auto _ : state) {
        // Bulk write
        for (int i = 0; i < bulk_size; i++) {
            ring_buffer_write(buffer, &metrics_batch[i], sizeof(vpn_metrics_t));
        }
        
        // Bulk read
        vpn_metrics_t read_metrics;
        for (int i = 0; i < bulk_size; i++) {
            ring_buffer_read(buffer, &read_metrics, sizeof(vpn_metrics_t));
        }
    }
    
    state.SetItemsProcessed(state.iterations() * bulk_size * 2); // *2 for read+write
    state.SetBytesProcessed(state.iterations() * bulk_size * 2 * sizeof(vpn_metrics_t));
    
    ring_buffer_destroy(buffer);
}

BENCHMARK(BM_RingBufferBulkOperations)
    ->Arg(1000)->Arg(10000)->Arg(100000)
    ->Unit(benchmark::kMicrosecond);

static void BM_RingBufferMemoryAccess(benchmark::State& state) {
    ring_buffer_t* buffer = ring_buffer_create(state.range(0));
    
    // Different sized payloads
    struct small_payload { uint64_t a, b; };
    struct medium_payload { uint64_t data[16]; };
    struct large_payload { uint64_t data[128]; };
    
    small_payload small = {1, 2};
    medium_payload medium = {};
    large_payload large = {};
    
    int operation = 0;
    for (auto _ : state) {
        switch (operation % 3) {
            case 0:
                ring_buffer_write(buffer, &small, sizeof(small));
                ring_buffer_read(buffer, &small, sizeof(small));
                break;
            case 1:
                ring_buffer_write(buffer, &medium, sizeof(medium));
                ring_buffer_read(buffer, &medium, sizeof(medium));
                break;
            case 2:
                ring_buffer_write(buffer, &large, sizeof(large));
                ring_buffer_read(buffer, &large, sizeof(large));
                break;
        }
        operation++;
    }
    
    state.SetItemsProcessed(state.iterations());
    
    ring_buffer_destroy(buffer);
}

BENCHMARK(BM_RingBufferMemoryAccess)
    ->Arg(10000)
    ->Unit(benchmark::kNanosecond);

BENCHMARK_MAIN();