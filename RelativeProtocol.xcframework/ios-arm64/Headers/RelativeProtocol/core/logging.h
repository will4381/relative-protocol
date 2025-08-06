#ifndef RELATIVE_VPN_LOGGING_H
#define RELATIVE_VPN_LOGGING_H

#include <stdio.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum log_level {
    LOG_SILENT = 0,
    LOG_CRITICAL = 1,
    LOG_ERROR = 2,
    LOG_WARN = 3,
    LOG_INFO = 4,
    LOG_DEBUG = 5,
    LOG_TRACE = 6
} log_level_t;

#if ENABLE_LOGGING

#define LOG_CRITICAL_ENABLED 1
#define LOG_ERROR_ENABLED 1
#define LOG_WARN_ENABLED 1
#define LOG_INFO_ENABLED 1
#define LOG_DEBUG_ENABLED 1
#define LOG_TRACE_ENABLED 1

void log_init(log_level_t level);
log_level_t log_level_from_string(const char *level_str);
void log_set_callback(void (*callback)(const char *message, void *user_data), void *user_data);
void log_message(log_level_t level, const char *file, int line, const char *fmt, ...);

#define LOG_CRITICAL(fmt, ...) log_message(LOG_CRITICAL, __FILE__, __LINE__, fmt, ##__VA_ARGS__)
#define LOG_ERROR(fmt, ...) log_message(LOG_ERROR, __FILE__, __LINE__, fmt, ##__VA_ARGS__)
#define LOG_WARN(fmt, ...) log_message(LOG_WARN, __FILE__, __LINE__, fmt, ##__VA_ARGS__)
#define LOG_INFO(fmt, ...) log_message(LOG_INFO, __FILE__, __LINE__, fmt, ##__VA_ARGS__)
#define LOG_DEBUG(fmt, ...) log_message(LOG_DEBUG, __FILE__, __LINE__, fmt, ##__VA_ARGS__)
#define LOG_TRACE(fmt, ...) log_message(LOG_TRACE, __FILE__, __LINE__, fmt, ##__VA_ARGS__)

#else

#define LOG_CRITICAL_ENABLED 0
#define LOG_ERROR_ENABLED 0
#define LOG_WARN_ENABLED 0
#define LOG_INFO_ENABLED 0
#define LOG_DEBUG_ENABLED 0
#define LOG_TRACE_ENABLED 0

#define log_init(level) do {} while(0)
#define log_set_callback(callback, user_data) do {} while(0)
#define LOG_CRITICAL(fmt, ...) do {} while(0)
#define LOG_ERROR(fmt, ...) do {} while(0)
#define LOG_WARN(fmt, ...) do {} while(0)
#define LOG_INFO(fmt, ...) do {} while(0)
#define LOG_DEBUG(fmt, ...) do {} while(0)
#define LOG_TRACE(fmt, ...) do {} while(0)

#endif

#ifdef __cplusplus
}
#endif

#endif