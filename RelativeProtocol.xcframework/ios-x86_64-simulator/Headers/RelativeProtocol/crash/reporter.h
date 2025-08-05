#ifndef RELATIVE_VPN_CRASH_REPORTER_H
#define RELATIVE_VPN_CRASH_REPORTER_H

#include <stdint.h>
#include <stdbool.h>
#include <signal.h>

typedef struct crash_reporter crash_reporter_t;

typedef enum crash_type {
    CRASH_TYPE_SEGFAULT = 1,
    CRASH_TYPE_ABORT = 2,
    CRASH_TYPE_BUS_ERROR = 3,
    CRASH_TYPE_FLOATING_POINT = 4,
    CRASH_TYPE_ILLEGAL_INSTRUCTION = 5,
    CRASH_TYPE_ASSERTION = 6,
    CRASH_TYPE_OUT_OF_MEMORY = 7,
    CRASH_TYPE_CUSTOM = 8
} crash_type_t;

typedef struct crash_info {
    crash_type_t type;
    int signal_number;
    int signal_code;
    void *fault_address;
    uint64_t timestamp_ns;
    char thread_name[64];
    uint32_t thread_id;
    uint32_t process_id;
    char process_name[256];
    char version[32];
    char build_id[64];
    void *stack_trace[64];
    size_t stack_trace_count;
    char system_info[512];
    char custom_data[1024];
} crash_info_t;

typedef enum crash_reporter_flags {
    CRASH_REPORTER_ENABLE_STACK_TRACES = 1 << 0,
    CRASH_REPORTER_ENABLE_SYSTEM_INFO = 1 << 1,
    CRASH_REPORTER_ENABLE_MEMORY_DUMP = 1 << 2,
    CRASH_REPORTER_ENABLE_THREAD_INFO = 1 << 3,
    CRASH_REPORTER_ENABLE_NETWORK_STATE = 1 << 4,
    CRASH_REPORTER_ENABLE_VPN_STATE = 1 << 5
} crash_reporter_flags_t;

typedef void (*crash_callback_t)(const crash_info_t *crash_info, void *user_data);

// Core crash reporter functions
crash_reporter_t *crash_reporter_create(void);
void crash_reporter_destroy(crash_reporter_t *reporter);

bool crash_reporter_initialize(crash_reporter_t *reporter, crash_reporter_flags_t flags);
bool crash_reporter_enable(crash_reporter_t *reporter);
bool crash_reporter_disable(crash_reporter_t *reporter);

void crash_reporter_set_callback(crash_reporter_t *reporter, crash_callback_t callback, void *user_data);
void crash_reporter_set_version_info(crash_reporter_t *reporter, const char *version, const char *build_id);
void crash_reporter_set_custom_data(crash_reporter_t *reporter, const char *key, const char *value);

// Manual crash reporting
bool crash_reporter_report_crash(crash_reporter_t *reporter, crash_type_t type, const char *reason);
bool crash_reporter_report_assertion(crash_reporter_t *reporter, const char *condition, const char *file, int line);

// Stack trace utilities
size_t crash_reporter_capture_stack_trace(void **buffer, size_t max_frames);
bool crash_reporter_symbolicate_address(void *address, char *symbol, size_t symbol_size, 
                                       char *filename, size_t filename_size, int *line_number);

// System information
bool crash_reporter_get_system_info(char *buffer, size_t buffer_size);
bool crash_reporter_get_memory_info(char *buffer, size_t buffer_size);
bool crash_reporter_get_thread_info(char *buffer, size_t buffer_size);

// Crash report persistence
bool crash_reporter_save_crash_report(const crash_info_t *crash_info, const char *filepath);
bool crash_reporter_load_crash_report(crash_info_t *crash_info, const char *filepath);

// Crash report analysis
typedef struct crash_stats {
    uint32_t total_crashes;
    uint32_t segfault_crashes;
    uint32_t abort_crashes;
    uint32_t bus_error_crashes;
    uint32_t floating_point_crashes;
    uint32_t illegal_instruction_crashes;
    uint32_t assertion_crashes;
    uint32_t out_of_memory_crashes;
    uint32_t custom_crashes;
    uint64_t first_crash_time;
    uint64_t last_crash_time;
    double crash_rate_per_hour;
} crash_stats_t;

void crash_reporter_get_stats(crash_reporter_t *reporter, crash_stats_t *stats);
void crash_reporter_reset_stats(crash_reporter_t *reporter);

// Utility macros
#define CRASH_ASSERT(condition) \
    do { \
        if (!(condition)) { \
            crash_reporter_report_assertion(g_crash_reporter, #condition, __FILE__, __LINE__); \
            abort(); \
        } \
    } while(0)

#define CRASH_LOG_FATAL(format, ...) \
    do { \
        char _crash_msg[512]; \
        snprintf(_crash_msg, sizeof(_crash_msg), format, ##__VA_ARGS__); \
        crash_reporter_report_crash(g_crash_reporter, CRASH_TYPE_CUSTOM, _crash_msg); \
    } while(0)

// Global crash reporter instance (should be initialized early)
extern crash_reporter_t *g_crash_reporter;

#endif