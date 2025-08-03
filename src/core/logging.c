#include "core/logging.h"
#include <stdarg.h>
#include <string.h>
#include <strings.h>  // For strcasecmp on macOS
#include <time.h>
#include <pthread.h>

#if ENABLE_LOGGING

static log_level_t current_log_level = LOG_INFO;
static void (*log_callback)(const char *message, void *user_data) = NULL;
static void *log_user_data = NULL;
static pthread_mutex_t log_mutex = PTHREAD_MUTEX_INITIALIZER;

static const char *level_strings[] = {
    "SILENT", "CRITICAL", "ERROR", "WARN", "INFO", "DEBUG", "TRACE"
};

void log_init(log_level_t level) {
    pthread_mutex_lock(&log_mutex);
    current_log_level = level;
    pthread_mutex_unlock(&log_mutex);
}

log_level_t log_level_from_string(const char *level_str) {
    if (!level_str) return LOG_INFO;
    
    if (strcasecmp(level_str, "SILENT") == 0) return LOG_SILENT;
    if (strcasecmp(level_str, "CRITICAL") == 0) return LOG_CRITICAL;
    if (strcasecmp(level_str, "ERROR") == 0) return LOG_ERROR;
    if (strcasecmp(level_str, "WARN") == 0) return LOG_WARN;
    if (strcasecmp(level_str, "INFO") == 0) return LOG_INFO;
    if (strcasecmp(level_str, "DEBUG") == 0) return LOG_DEBUG;
    if (strcasecmp(level_str, "TRACE") == 0) return LOG_TRACE;
    
    return LOG_INFO; // Default
}

void log_set_callback(void (*callback)(const char *message, void *user_data), void *user_data) {
    pthread_mutex_lock(&log_mutex);
    log_callback = callback;
    log_user_data = user_data;
    pthread_mutex_unlock(&log_mutex);
}

void log_message(log_level_t level, const char *file, int line, const char *fmt, ...) {
    if (level > current_log_level) {
        return;
    }
    
    pthread_mutex_lock(&log_mutex);
    
    char buffer[1024];
    char timestamp[32];
    time_t now = time(NULL);
    struct tm *tm_info = localtime(&now);
    strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", tm_info);
    
    const char *filename = strrchr(file, '/');
    filename = filename ? filename + 1 : file;
    
    va_list args;
    va_start(args, fmt);
    
    int prefix_len = snprintf(buffer, sizeof(buffer), "[%s] %s %s:%d - ", 
                             timestamp, level_strings[level], filename, line);
    
    if (prefix_len > 0 && prefix_len < sizeof(buffer)) {
        vsnprintf(buffer + prefix_len, sizeof(buffer) - prefix_len, fmt, args);
    }
    
    va_end(args);
    
    if (log_callback) {
        log_callback(buffer, log_user_data);
    } else {
        fprintf(stderr, "%s\n", buffer);
        fflush(stderr);
    }
    
    pthread_mutex_unlock(&log_mutex);
}

#endif