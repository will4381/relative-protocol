#include <gtest/gtest.h>
#include "core/logging.h"
#include <string>
#include <vector>

class LoggingTest : public ::testing::Test {
protected:
    void SetUp() override {
        log_messages.clear();
        log_init(LOG_DEBUG);
        log_set_callback([](const char* message, void* user_data) {
            auto* messages = static_cast<std::vector<std::string>*>(user_data);
            messages->push_back(std::string(message));
        }, &log_messages);
    }
    
    void TearDown() override {
        log_set_callback(nullptr, nullptr);
    }
    
    std::vector<std::string> log_messages;
};

#if ENABLE_LOGGING

TEST_F(LoggingTest, BasicLogging) {
    LOG_ERROR("Test error message");
    LOG_WARN("Test warning message");
    LOG_INFO("Test info message");
    LOG_DEBUG("Test debug message");
    
    EXPECT_EQ(log_messages.size(), 4);
    EXPECT_NE(log_messages[0].find("ERROR"), std::string::npos);
    EXPECT_NE(log_messages[1].find("WARN"), std::string::npos);
    EXPECT_NE(log_messages[2].find("INFO"), std::string::npos);
    EXPECT_NE(log_messages[3].find("DEBUG"), std::string::npos);
}

TEST_F(LoggingTest, LogLevels) {
    log_init(LOG_WARN);
    log_messages.clear();
    
    LOG_ERROR("Error message");
    LOG_WARN("Warning message");
    LOG_INFO("Info message");
    LOG_DEBUG("Debug message");
    
    EXPECT_EQ(log_messages.size(), 2);
    EXPECT_NE(log_messages[0].find("ERROR"), std::string::npos);
    EXPECT_NE(log_messages[1].find("WARN"), std::string::npos);
}

TEST_F(LoggingTest, FormattedLogging) {
    LOG_INFO("Formatted message: %d %s", 42, "test");
    
    EXPECT_EQ(log_messages.size(), 1);
    EXPECT_NE(log_messages[0].find("42"), std::string::npos);
    EXPECT_NE(log_messages[0].find("test"), std::string::npos);
}

#else

TEST_F(LoggingTest, LoggingDisabled) {
    LOG_ERROR("This should not appear");
    LOG_WARN("This should not appear");
    LOG_INFO("This should not appear");
    LOG_DEBUG("This should not appear");
    
    EXPECT_EQ(log_messages.size(), 0);
}

#endif