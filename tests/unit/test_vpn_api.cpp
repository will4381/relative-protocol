#include <gtest/gtest.h>
#include "api/relative_vpn.h"
#include <thread>
#include <chrono>

class VPNAPITest : public ::testing::Test {
protected:
    void SetUp() override {
        config = {};
        config.utun_name = nullptr;
        config.mtu = 1500;
        config.ipv4_enabled = true;
        config.ipv6_enabled = true;
        config.enable_nat64 = false;
        config.enable_dns_leak_protection = true;
        config.enable_ipv6_leak_protection = true;
        config.enable_kill_switch = false;
        config.enable_webrtc_leak_protection = true;
        config.tunnel_mtu = 1500;
        config.dns_servers[0] = 0x08080808; // 8.8.8.8
        config.dns_server_count = 1;
        config.dns_cache_size = 1024;
        config.metrics_buffer_size = 4096;
        config.reachability_monitoring = true;
        config.log_level = const_cast<char*>("INFO");
    }
    
    void TearDown() override {
        if (vpn_is_running()) {
            vpn_stop();
        }
    }
    
    vpn_config_t config;
};

TEST_F(VPNAPITest, InvalidConfigValidation) {
    vpn_config_t invalid_config = {};
    
    invalid_config.mtu = 0;
    EXPECT_EQ(vpn_start(&invalid_config), VPN_ERROR_INVALID_CONFIG);
    
    invalid_config = config;
    invalid_config.mtu = 100;
    EXPECT_EQ(vpn_start(&invalid_config), VPN_ERROR_INVALID_CONFIG);
    
    invalid_config = config;
    invalid_config.mtu = 70000;
    EXPECT_EQ(vpn_start(&invalid_config), VPN_ERROR_INVALID_CONFIG);
    
    invalid_config = config;
    invalid_config.ipv4_enabled = false;
    invalid_config.ipv6_enabled = false;
    EXPECT_EQ(vpn_start(&invalid_config), VPN_ERROR_INVALID_CONFIG);
    
    invalid_config = config;
    invalid_config.dns_cache_size = 0;
    EXPECT_EQ(vpn_start(&invalid_config), VPN_ERROR_INVALID_CONFIG);
    
    invalid_config = config;
    invalid_config.metrics_buffer_size = 0;
    EXPECT_EQ(vpn_start(&invalid_config), VPN_ERROR_INVALID_CONFIG);
}

TEST_F(VPNAPITest, StartStopBasic) {
    EXPECT_FALSE(vpn_is_running());
    
    vpn_status_t result = vpn_start(&config);
    if (result == VPN_ERROR_PERMISSION) {
        GTEST_SKIP() << "Skipping test due to permission requirements";
    }
    EXPECT_EQ(result, VPN_SUCCESS);
    EXPECT_TRUE(vpn_is_running());
    
    EXPECT_EQ(vpn_stop(), VPN_SUCCESS);
    EXPECT_FALSE(vpn_is_running());
}

TEST_F(VPNAPITest, DoubleStart) {
    vpn_status_t result = vpn_start(&config);
    if (result == VPN_ERROR_PERMISSION) {
        GTEST_SKIP() << "Skipping test due to permission requirements";
    }
    EXPECT_EQ(result, VPN_SUCCESS);
    
    EXPECT_EQ(vpn_start(&config), VPN_ERROR_ALREADY_RUNNING);
    
    EXPECT_EQ(vpn_stop(), VPN_SUCCESS);
}

TEST_F(VPNAPITest, StopWithoutStart) {
    EXPECT_EQ(vpn_stop(), VPN_ERROR_NOT_RUNNING);
}

TEST_F(VPNAPITest, MetricsRetrieval) {
    vpn_status_t result = vpn_start(&config);
    if (result == VPN_ERROR_PERMISSION) {
        GTEST_SKIP() << "Skipping test due to permission requirements";
    }
    EXPECT_EQ(result, VPN_SUCCESS);
    
    vpn_metrics_t metrics;
    EXPECT_EQ(vpn_get_metrics(&metrics), VPN_SUCCESS);
    
    EXPECT_EQ(metrics.bytes_in, 0);
    EXPECT_EQ(metrics.bytes_out, 0);
    EXPECT_EQ(metrics.packets_in, 0);
    EXPECT_EQ(metrics.packets_out, 0);
    
    EXPECT_EQ(vpn_stop(), VPN_SUCCESS);
}

TEST_F(VPNAPITest, MetricsCallback) {
    static bool callback_called = false;
    static vpn_metrics_t received_metrics;
    
    auto callback = [](const vpn_metrics_t *metrics, void *user_data) {
        callback_called = true;
        received_metrics = *metrics;
        EXPECT_EQ(user_data, reinterpret_cast<void*>(0xDEADBEEF));
    };
    
    vpn_status_t result = vpn_start(&config);
    if (result == VPN_ERROR_PERMISSION) {
        GTEST_SKIP() << "Skipping test due to permission requirements";
    }
    EXPECT_EQ(result, VPN_SUCCESS);
    
    EXPECT_EQ(vpn_set_metrics_callback(callback, reinterpret_cast<void*>(0xDEADBEEF)), VPN_SUCCESS);
    
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    
    EXPECT_EQ(vpn_stop(), VPN_SUCCESS);
}

TEST_F(VPNAPITest, PacketInjection) {
    vpn_status_t result = vpn_start(&config);
    if (result == VPN_ERROR_PERMISSION) {
        GTEST_SKIP() << "Skipping test due to permission requirements";
    }
    EXPECT_EQ(result, VPN_SUCCESS);
    
    uint8_t test_packet[] = {
        0x45, 0x00, 0x00, 0x14,
        0x00, 0x00, 0x40, 0x00,
        0x40, 0x01, 0x00, 0x00,
        0x7f, 0x00, 0x00, 0x01,
        0x7f, 0x00, 0x00, 0x01
    };
    
    EXPECT_EQ(vpn_inject(test_packet, sizeof(test_packet)), VPN_SUCCESS);
    EXPECT_EQ(vpn_inject(nullptr, 0), VPN_ERROR_INVALID_CONFIG);
    
    EXPECT_EQ(vpn_stop(), VPN_SUCCESS);
}

TEST_F(VPNAPITest, ErrorStrings) {
    EXPECT_STREQ(vpn_error_string(VPN_SUCCESS), "Success");
    EXPECT_STREQ(vpn_error_string(VPN_ERROR_INVALID_CONFIG), "Invalid configuration");
    EXPECT_STREQ(vpn_error_string(VPN_ERROR_UTUN_FAILED), "Failed to create utun interface");
    EXPECT_STREQ(vpn_error_string(VPN_ERROR_ALREADY_RUNNING), "VPN is already running");
    EXPECT_STREQ(vpn_error_string(VPN_ERROR_NOT_RUNNING), "VPN is not running");
    EXPECT_STREQ(vpn_error_string(VPN_ERROR_MEMORY), "Memory allocation failed");
    EXPECT_STREQ(vpn_error_string(VPN_ERROR_NETWORK), "Network error");
    EXPECT_STREQ(vpn_error_string(VPN_ERROR_PERMISSION), "Permission denied");
    
    EXPECT_STREQ(vpn_error_string(static_cast<vpn_status_t>(-999)), "Unknown error");
}