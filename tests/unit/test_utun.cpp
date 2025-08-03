#include <gtest/gtest.h>
#include "packet/utun.h"
#include <thread>
#include <chrono>

class UTunTest : public ::testing::Test {
protected:
    void SetUp() override {
        handle = nullptr;
    }
    
    void TearDown() override {
        if (handle) {
            utun_destroy(handle);
        }
    }
    
    utun_handle_t *handle;
};

TEST_F(UTunTest, CreateDestroy) {
    handle = utun_create(nullptr, 1500);
    if (handle == nullptr) {
        GTEST_SKIP() << "Skipping test due to permission requirements or platform limitations";
    }
    
    EXPECT_NE(handle, nullptr);
    EXPECT_GE(utun_get_fd(handle), 0);
    EXPECT_NE(utun_get_name(handle), nullptr);
    EXPECT_EQ(utun_get_mtu(handle), 1500);
    
    utun_destroy(handle);
    handle = nullptr;
}

TEST_F(UTunTest, MTUOperations) {
    handle = utun_create(nullptr, 1500);
    if (handle == nullptr) {
        GTEST_SKIP() << "Skipping test due to permission requirements";
    }
    
    EXPECT_EQ(utun_get_mtu(handle), 1500);
    EXPECT_TRUE(utun_set_mtu(handle, 1400));
    EXPECT_EQ(utun_get_mtu(handle), 1400);
    
    EXPECT_FALSE(utun_set_mtu(handle, 0));
    EXPECT_FALSE(utun_set_mtu(handle, 70000));
}

TEST_F(UTunTest, PacketOperations) {
    handle = utun_create(nullptr, 1500);
    if (handle == nullptr) {
        GTEST_SKIP() << "Skipping test due to permission requirements";
    }
    
    uint8_t test_packet[] = {
        0x45, 0x00, 0x00, 0x1c,  // IPv4 header
        0x00, 0x01, 0x00, 0x00,
        0x40, 0x01, 0x00, 0x00,
        0x7f, 0x00, 0x00, 0x01,
        0x7f, 0x00, 0x00, 0x01,
        0x08, 0x00, 0xf7, 0xfc,  // ICMP
        0x00, 0x00, 0x00, 0x00
    };
    
    ssize_t written = utun_write(handle, test_packet, sizeof(test_packet));
    EXPECT_GT(written, 0);
    
    uint8_t read_buffer[1500];
    ssize_t read_bytes = utun_read(handle, read_buffer, sizeof(read_buffer));
    
    EXPECT_TRUE(read_bytes > 0 || read_bytes == -1);
}

TEST_F(UTunTest, ReadLoopCallback) {
    handle = utun_create(nullptr, 1500);
    if (handle == nullptr) {
        GTEST_SKIP() << "Skipping test due to permission requirements";
    }
    
    bool callback_called = false;
    packet_info_t received_packet;
    
    auto callback = [](const packet_info_t *packet, void *user_data) {
        bool *called = static_cast<bool*>(user_data);
        *called = true;
    };
    
    EXPECT_TRUE(utun_start_read_loop(handle, callback, &callback_called));
    
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    
    utun_stop_read_loop(handle);
}

TEST_F(UTunTest, InvalidInputs) {
    EXPECT_EQ(utun_get_fd(nullptr), -1);
    EXPECT_EQ(utun_get_name(nullptr), nullptr);
    EXPECT_EQ(utun_get_mtu(nullptr), 0);
    EXPECT_FALSE(utun_set_mtu(nullptr, 1500));
    
    EXPECT_EQ(utun_read(nullptr, nullptr, 0), -1);
    EXPECT_EQ(utun_write(nullptr, nullptr, 0), -1);
    
    EXPECT_FALSE(utun_start_read_loop(nullptr, nullptr, nullptr));
    
    utun_stop_read_loop(nullptr);
    utun_destroy(nullptr);
}