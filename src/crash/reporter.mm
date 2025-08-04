extern "C" {
#include "crash/reporter.h"
#include "core/logging.h"
}
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <pthread.h>
#include <sys/utsname.h>
#include <sys/sysctl.h>
#include <execinfo.h>
#include <dlfcn.h>
#include <time.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
// libproc.h not available on iOS
#include <mach/mach.h>
#include <mach/thread_info.h>
#include <mach/thread_act.h>

#ifdef TARGET_OS_IOS
#include <UIKit/UIDevice.h>
#endif

#define MAX_CRASH_REPORTS 100
#define CRASH_REPORT_DIR "/tmp/vpn_crashes"
#define MAX_CUSTOM_DATA_ENTRIES 32

typedef struct custom_data_entry {
    char key[64];
    char value[256];
} custom_data_entry_t;

struct crash_reporter {
    bool initialized;
    bool enabled;
    crash_reporter_flags_t flags;
    crash_callback_t callback;
    void *callback_user_data;
    
    // Version information
    char version[32];
    char build_id[64];
    
    // Custom data
    custom_data_entry_t custom_data[MAX_CUSTOM_DATA_ENTRIES];
    size_t custom_data_count;
    
    // Statistics
    crash_stats_t stats;
    
    // Signal handlers
    struct sigaction old_handlers[32];
    
    // Thread safety
    pthread_mutex_t mutex;
};

// Global crash reporter instance
crash_reporter_t *g_crash_reporter = NULL;

// Signal handler
static void crash_signal_handler(int sig, siginfo_t *info, void *context);

// Helper functions
static const char* crash_type_to_string(crash_type_t type);
static const char* signal_to_string(int sig);
static bool create_crash_report_directory(void);
static void populate_system_info(crash_info_t *crash_info);
static void populate_thread_info(crash_info_t *crash_info);
static void update_crash_stats(crash_reporter_t *reporter, crash_type_t type);

crash_reporter_t *crash_reporter_create(void) {
    crash_reporter_t *reporter = (crash_reporter_t *)calloc(1, sizeof(crash_reporter_t));
    if (!reporter) {
        LOG_ERROR("Failed to allocate crash reporter");
        return NULL;
    }
    
    if (pthread_mutex_init(&reporter->mutex, NULL) != 0) {
        LOG_ERROR("Failed to initialize crash reporter mutex");
        free(reporter);
        return NULL;
    }
    
    // Initialize default version info
    strncpy(reporter->version, "1.0.0", sizeof(reporter->version) - 1);
    strncpy(reporter->build_id, "unknown", sizeof(reporter->build_id) - 1);
    
    reporter->stats.first_crash_time = 0;
    reporter->stats.last_crash_time = 0;
    
    LOG_INFO("Crash reporter created");
    return reporter;
}

void crash_reporter_destroy(crash_reporter_t *reporter) {
    if (!reporter) return;
    
    pthread_mutex_lock(&reporter->mutex);
    
    if (reporter->enabled) {
        crash_reporter_disable(reporter);
    }
    
    pthread_mutex_unlock(&reporter->mutex);
    pthread_mutex_destroy(&reporter->mutex);
    
    free(reporter);
    LOG_INFO("Crash reporter destroyed");
}

bool crash_reporter_initialize(crash_reporter_t *reporter, crash_reporter_flags_t flags) {
    if (!reporter) return false;
    
    pthread_mutex_lock(&reporter->mutex);
    
    if (reporter->initialized) {
        LOG_WARN("Crash reporter already initialized");
        pthread_mutex_unlock(&reporter->mutex);
        return true;
    }
    
    reporter->flags = flags;
    
    // Create crash report directory
    if (!create_crash_report_directory()) {
        LOG_ERROR("Failed to create crash report directory");
        pthread_mutex_unlock(&reporter->mutex);
        return false;
    }
    
    // Set global instance
    g_crash_reporter = reporter;
    
    reporter->initialized = true;
    
    pthread_mutex_unlock(&reporter->mutex);
    
    LOG_INFO("Crash reporter initialized with flags: 0x%x", flags);
    return true;
}

bool crash_reporter_enable(crash_reporter_t *reporter) {
    if (!reporter || !reporter->initialized) {
        return false;
    }
    
    pthread_mutex_lock(&reporter->mutex);
    
    if (reporter->enabled) {
        pthread_mutex_unlock(&reporter->mutex);
        return true;
    }
    
    // Install signal handlers
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_sigaction = crash_signal_handler;
    sa.sa_flags = SA_SIGINFO | SA_ONSTACK;
    sigemptyset(&sa.sa_mask);
    
    // Handle critical signals
    int signals[] = {SIGSEGV, SIGABRT, SIGBUS, SIGFPE, SIGILL, SIGTERM};
    size_t signal_count = sizeof(signals) / sizeof(signals[0]);
    
    for (size_t i = 0; i < signal_count; i++) {
        if (sigaction(signals[i], &sa, &reporter->old_handlers[signals[i]]) != 0) {
            LOG_ERROR("Failed to install signal handler for signal %d: %s", 
                     signals[i], strerror(errno));
            
            // Restore previously installed handlers
            for (size_t j = 0; j < i; j++) {
                sigaction(signals[j], &reporter->old_handlers[signals[j]], NULL);
            }
            
            pthread_mutex_unlock(&reporter->mutex);
            return false;
        }
    }
    
    reporter->enabled = true;
    
    pthread_mutex_unlock(&reporter->mutex);
    
    LOG_INFO("Crash reporter enabled");
    return true;
}

bool crash_reporter_disable(crash_reporter_t *reporter) {
    if (!reporter || !reporter->enabled) {
        return false;
    }
    
    pthread_mutex_lock(&reporter->mutex);
    
    // Restore original signal handlers
    int signals[] = {SIGSEGV, SIGABRT, SIGBUS, SIGFPE, SIGILL, SIGTERM};
    size_t signal_count = sizeof(signals) / sizeof(signals[0]);
    
    for (size_t i = 0; i < signal_count; i++) {
        sigaction(signals[i], &reporter->old_handlers[signals[i]], NULL);
    }
    
    reporter->enabled = false;
    
    pthread_mutex_unlock(&reporter->mutex);
    
    LOG_INFO("Crash reporter disabled");
    return true;
}

void crash_reporter_set_callback(crash_reporter_t *reporter, crash_callback_t callback, void *user_data) {
    if (!reporter) return;
    
    pthread_mutex_lock(&reporter->mutex);
    reporter->callback = callback;
    reporter->callback_user_data = user_data;
    pthread_mutex_unlock(&reporter->mutex);
}

void crash_reporter_set_version_info(crash_reporter_t *reporter, const char *version, const char *build_id) {
    if (!reporter || !version || !build_id) return;
    
    pthread_mutex_lock(&reporter->mutex);
    strncpy(reporter->version, version, sizeof(reporter->version) - 1);
    strncpy(reporter->build_id, build_id, sizeof(reporter->build_id) - 1);
    pthread_mutex_unlock(&reporter->mutex);
}

void crash_reporter_set_custom_data(crash_reporter_t *reporter, const char *key, const char *value) {
    if (!reporter || !key || !value) return;
    
    pthread_mutex_lock(&reporter->mutex);
    
    // Check if key already exists
    for (size_t i = 0; i < reporter->custom_data_count; i++) {
        if (strcmp(reporter->custom_data[i].key, key) == 0) {
            strncpy(reporter->custom_data[i].value, value, sizeof(reporter->custom_data[i].value) - 1);
            pthread_mutex_unlock(&reporter->mutex);
            return;
        }
    }
    
    // Add new entry if space available
    if (reporter->custom_data_count < MAX_CUSTOM_DATA_ENTRIES) {
        strncpy(reporter->custom_data[reporter->custom_data_count].key, key, 
                sizeof(reporter->custom_data[reporter->custom_data_count].key) - 1);
        strncpy(reporter->custom_data[reporter->custom_data_count].value, value, 
                sizeof(reporter->custom_data[reporter->custom_data_count].value) - 1);
        reporter->custom_data_count++;
    }
    
    pthread_mutex_unlock(&reporter->mutex);
}

bool crash_reporter_report_crash(crash_reporter_t *reporter, crash_type_t type, const char *reason) {
    if (!reporter || !reporter->initialized) {
        return false;
    }
    
    crash_info_t crash_info = {};
    crash_info.type = type;
    crash_info.timestamp_ns = clock_gettime_nsec_np(CLOCK_MONOTONIC);
    crash_info.process_id = getpid();
    crash_info.thread_id = (uint32_t)(uintptr_t)pthread_self();
    
    // Get process name
    // proc_name not available on iOS, use alternative
    strncpy(crash_info.process_name, "RelativeVPN", sizeof(crash_info.process_name) - 1);
    
    // Get thread name
    pthread_getname_np(pthread_self(), crash_info.thread_name, sizeof(crash_info.thread_name));
    
    // Copy version info
    strncpy(crash_info.version, reporter->version, sizeof(crash_info.version) - 1);
    strncpy(crash_info.build_id, reporter->build_id, sizeof(crash_info.build_id) - 1);
    
    // Add custom data
    if (reason) {
        strncpy(crash_info.custom_data, reason, sizeof(crash_info.custom_data) - 1);
    }
    
    // Capture stack trace if enabled
    if (reporter->flags & CRASH_REPORTER_ENABLE_STACK_TRACES) {
        crash_info.stack_trace_count = crash_reporter_capture_stack_trace(
            crash_info.stack_trace, sizeof(crash_info.stack_trace) / sizeof(crash_info.stack_trace[0]));
    }
    
    // Populate system info if enabled
    if (reporter->flags & CRASH_REPORTER_ENABLE_SYSTEM_INFO) {
        populate_system_info(&crash_info);
    }
    
    // Populate thread info if enabled
    if (reporter->flags & CRASH_REPORTER_ENABLE_THREAD_INFO) {
        populate_thread_info(&crash_info);
    }
    
    // Update statistics
    update_crash_stats(reporter, type);
    
    // Call user callback
    if (reporter->callback) {
        reporter->callback(&crash_info, reporter->callback_user_data);
    }
    
    // Save crash report
    char filepath[512];
    snprintf(filepath, sizeof(filepath), "%s/crash_%llu_%u.log", 
             CRASH_REPORT_DIR, crash_info.timestamp_ns, crash_info.process_id);
    
    crash_reporter_save_crash_report(&crash_info, filepath);
    
    LOG_ERROR("Crash reported: %s - %s", crash_type_to_string(type), reason ? reason : "No reason provided");
    
    return true;
}

bool crash_reporter_report_assertion(crash_reporter_t *reporter, const char *condition, const char *file, int line) {
    if (!reporter) return false;
    
    char reason[512];
    snprintf(reason, sizeof(reason), "Assertion failed: %s at %s:%d", 
             condition ? condition : "unknown", file ? file : "unknown", line);
    
    return crash_reporter_report_crash(reporter, CRASH_TYPE_ASSERTION, reason);
}

size_t crash_reporter_capture_stack_trace(void **buffer, size_t max_frames) {
    if (!buffer || max_frames == 0) return 0;
    
    return backtrace(buffer, (int)max_frames);
}

bool crash_reporter_symbolicate_address(void *address, char *symbol, size_t symbol_size, 
                                       char *filename, size_t filename_size, int *line_number) {
    if (!address || !symbol || !filename) return false;
    
    Dl_info info;
    if (dladdr(address, &info) != 0) {
        if (info.dli_sname) {
            strncpy(symbol, info.dli_sname, symbol_size - 1);
            symbol[symbol_size - 1] = '\0';
        } else {
            snprintf(symbol, symbol_size, "0x%lx", (unsigned long)address);
        }
        
        if (info.dli_fname) {
            strncpy(filename, info.dli_fname, filename_size - 1);
            filename[filename_size - 1] = '\0';
        } else {
            strncpy(filename, "unknown", filename_size - 1);
        }
        
        if (line_number) {
            *line_number = 0; // Line number not available from dladdr
        }
        
        return true;
    }
    
    return false;
}

static void crash_signal_handler(int sig, siginfo_t *info, void *context) {
    // This is a signal handler - we need to be very careful about what we do here
    // Only async-signal-safe functions should be called
    
    crash_reporter_t *reporter = g_crash_reporter;
    if (!reporter || !reporter->enabled) {
        // Restore default handler and re-raise
        signal(sig, SIG_DFL);
        raise(sig);
        return;
    }
    
    crash_info_t crash_info = {};
    
    // Map signal to crash type
    switch (sig) {
        case SIGSEGV:
            crash_info.type = CRASH_TYPE_SEGFAULT;
            break;
        case SIGABRT:
            crash_info.type = CRASH_TYPE_ABORT;
            break;
        case SIGBUS:
            crash_info.type = CRASH_TYPE_BUS_ERROR;
            break;
        case SIGFPE:
            crash_info.type = CRASH_TYPE_FLOATING_POINT;
            break;
        case SIGILL:
            crash_info.type = CRASH_TYPE_ILLEGAL_INSTRUCTION;
            break;
        default:
            crash_info.type = CRASH_TYPE_CUSTOM;
            break;
    }
    
    crash_info.signal_number = sig;
    crash_info.signal_code = info ? info->si_code : 0;
    crash_info.fault_address = info ? info->si_addr : NULL;
    crash_info.timestamp_ns = clock_gettime_nsec_np(CLOCK_MONOTONIC);
    crash_info.process_id = getpid();
    crash_info.thread_id = (uint32_t)(uintptr_t)pthread_self();
    
    // Capture stack trace (this should be async-signal-safe)
    if (reporter->flags & CRASH_REPORTER_ENABLE_STACK_TRACES) {
        crash_info.stack_trace_count = backtrace(crash_info.stack_trace, 
            sizeof(crash_info.stack_trace) / sizeof(crash_info.stack_trace[0]));
    }
    
    // Write minimal crash info to a file (using async-signal-safe functions)
    int fd = open("/tmp/vpn_crash_signal.log", O_CREAT | O_WRONLY | O_APPEND, 0644);
    if (fd >= 0) {
        char buffer[512];
        int len = snprintf(buffer, sizeof(buffer), 
                          "CRASH: sig=%d, pid=%u, tid=%u, addr=%p, time=%llu\n",
                          sig, crash_info.process_id, crash_info.thread_id, 
                          crash_info.fault_address, crash_info.timestamp_ns);
        write(fd, buffer, len);
        close(fd);
    }
    
    // Update stats (not thread-safe, but better than nothing)
    update_crash_stats(reporter, crash_info.type);
    
    // Restore default handler and re-raise to get core dump
    signal(sig, SIG_DFL);
    raise(sig);
}

bool crash_reporter_get_system_info(char *buffer, size_t buffer_size) {
    if (!buffer || buffer_size == 0) return false;
    
    struct utsname sys_info;
    if (uname(&sys_info) != 0) {
        strncpy(buffer, "System info unavailable", buffer_size - 1);
        return false;
    }
    
    // Get memory info
    uint64_t memory_size = 0;
    size_t size = sizeof(memory_size);
    sysctlbyname("hw.memsize", &memory_size, &size, NULL, 0);
    
    // Get CPU info
    char cpu_brand[256] = {0};
    size = sizeof(cpu_brand);
    sysctlbyname("machdep.cpu.brand_string", cpu_brand, &size, NULL, 0);
    
    int cpu_count = 0;
    size = sizeof(cpu_count);
    sysctlbyname("hw.ncpu", &cpu_count, &size, NULL, 0);
    
    snprintf(buffer, buffer_size,
             "System: %s %s %s\n"
             "CPU: %s (%d cores)\n"
             "Memory: %llu MB\n"
             "Architecture: %s",
             sys_info.sysname, sys_info.release, sys_info.version,
             cpu_brand[0] ? cpu_brand : "Unknown CPU",
             cpu_count,
             memory_size / (1024 * 1024),
             sys_info.machine);
    
    return true;
}

bool crash_reporter_get_memory_info(char *buffer, size_t buffer_size) {
    if (!buffer || buffer_size == 0) return false;
    
#ifdef TARGET_OS_IOS
    // Get iOS memory info
    vm_statistics64_data_t vm_stat;
    mach_msg_type_number_t host_size = sizeof(vm_statistics64_data_t) / sizeof(natural_t);
    
    kern_return_t kr = host_statistics64(mach_host_self(), HOST_VM_INFO64, 
                                        (host_info64_t)&vm_stat, &host_size);
    if (kr != KERN_SUCCESS) {
        strncpy(buffer, "Memory info unavailable", buffer_size - 1);
        return false;
    }
    
    vm_size_t page_size;
    kr = host_page_size(mach_host_self(), &page_size);
    if (kr != KERN_SUCCESS) {
        page_size = 4096; // Default page size
    }
    
    uint64_t free_memory = vm_stat.free_count * page_size;
    uint64_t active_memory = vm_stat.active_count * page_size;
    uint64_t inactive_memory = vm_stat.inactive_count * page_size;
    uint64_t wired_memory = vm_stat.wire_count * page_size;
    
    snprintf(buffer, buffer_size,
             "Memory Info:\n"
             "  Free: %llu MB\n"
             "  Active: %llu MB\n"
             "  Inactive: %llu MB\n"
             "  Wired: %llu MB\n"
             "  Page Size: %u bytes",
             free_memory / (1024 * 1024),
             active_memory / (1024 * 1024),
             inactive_memory / (1024 * 1024),
             wired_memory / (1024 * 1024),
             (unsigned long)page_size);
#else
    strncpy(buffer, "Memory info not available on this platform", buffer_size - 1);
#endif
    
    return true;
}

bool crash_reporter_get_thread_info(char *buffer, size_t buffer_size) {
    if (!buffer || buffer_size == 0) return false;
    
    char thread_name[64] = {0};
    pthread_getname_np(pthread_self(), thread_name, sizeof(thread_name));
    
    snprintf(buffer, buffer_size,
             "Thread Info:\n"
             "  Thread ID: %u\n"
             "  Thread Name: %s\n"
             "  Process ID: %u",
             (uint32_t)(uintptr_t)pthread_self(),
             thread_name[0] ? thread_name : "unnamed",
             getpid());
    
    return true;
}

bool crash_reporter_save_crash_report(const crash_info_t *crash_info, const char *filepath) {
    if (!crash_info || !filepath) return false;
    
    FILE *file = fopen(filepath, "w");
    if (!file) {
        return false;
    }
    
    // Write crash report header
    fprintf(file, "=== VPN CRASH REPORT ===\n");
    fprintf(file, "Crash Type: %s\n", crash_type_to_string(crash_info->type));
    fprintf(file, "Signal: %s (%d)\n", signal_to_string(crash_info->signal_number), crash_info->signal_number);
    fprintf(file, "Signal Code: %d\n", crash_info->signal_code);
    fprintf(file, "Fault Address: %p\n", crash_info->fault_address);
    fprintf(file, "Timestamp: %llu ns\n", crash_info->timestamp_ns);
    fprintf(file, "Process ID: %u\n", crash_info->process_id);
    fprintf(file, "Thread ID: %u\n", crash_info->thread_id);
    fprintf(file, "Process Name: %s\n", crash_info->process_name);
    fprintf(file, "Thread Name: %s\n", crash_info->thread_name);
    fprintf(file, "Version: %s\n", crash_info->version);
    fprintf(file, "Build ID: %s\n", crash_info->build_id);
    fprintf(file, "\n");
    
    // Write stack trace
    if (crash_info->stack_trace_count > 0) {
        fprintf(file, "=== STACK TRACE ===\n");
        for (size_t i = 0; i < crash_info->stack_trace_count; i++) {
            char symbol[256] = {0};
            char filename[512] = {0};
            int line_number = 0;
            
            if (crash_reporter_symbolicate_address(crash_info->stack_trace[i], 
                                                  symbol, sizeof(symbol),
                                                  filename, sizeof(filename),
                                                  &line_number)) {
                fprintf(file, "  #%zu: %s in %s\n", i, symbol, filename);
            } else {
                fprintf(file, "  #%zu: %p\n", i, crash_info->stack_trace[i]);
            }
        }
        fprintf(file, "\n");
    }
    
    // Write system info
    if (crash_info->system_info[0]) {
        fprintf(file, "=== SYSTEM INFO ===\n");
        fprintf(file, "%s\n\n", crash_info->system_info);
    }
    
    // Write custom data
    if (crash_info->custom_data[0]) {
        fprintf(file, "=== CUSTOM DATA ===\n");
        fprintf(file, "%s\n\n", crash_info->custom_data);
    }
    
    fclose(file);
    return true;
}

bool crash_reporter_load_crash_report(crash_info_t *crash_info, const char *filepath) {
    if (!crash_info || !filepath) return false;
    
    FILE *file = fopen(filepath, "r");
    if (!file) return false;
    
    // This is a simplified implementation - in practice you'd parse the entire file
    char line[512];
    while (fgets(line, sizeof(line), file)) {
        if (sscanf(line, "Process ID: %u", &crash_info->process_id) == 1) continue;
        if (sscanf(line, "Thread ID: %u", &crash_info->thread_id) == 1) continue;
        if (sscanf(line, "Timestamp: %llu", &crash_info->timestamp_ns) == 1) continue;
        // Parse other fields as needed
    }
    
    fclose(file);
    return true;
}

void crash_reporter_get_stats(crash_reporter_t *reporter, crash_stats_t *stats) {
    if (!reporter || !stats) return;
    
    pthread_mutex_lock(&reporter->mutex);
    memcpy(stats, &reporter->stats, sizeof(crash_stats_t));
    
    // Calculate crash rate
    if (reporter->stats.first_crash_time > 0 && reporter->stats.last_crash_time > reporter->stats.first_crash_time) {
        uint64_t time_span_ns = reporter->stats.last_crash_time - reporter->stats.first_crash_time;
        double hours = (double)time_span_ns / (1000000000.0 * 3600.0);
        if (hours > 0) {
            stats->crash_rate_per_hour = (double)reporter->stats.total_crashes / hours;
        }
    }
    
    pthread_mutex_unlock(&reporter->mutex);
}

void crash_reporter_reset_stats(crash_reporter_t *reporter) {
    if (!reporter) return;
    
    pthread_mutex_lock(&reporter->mutex);
    memset(&reporter->stats, 0, sizeof(crash_stats_t));
    pthread_mutex_unlock(&reporter->mutex);
}

static const char* crash_type_to_string(crash_type_t type) {
    switch (type) {
        case CRASH_TYPE_SEGFAULT: return "Segmentation Fault";
        case CRASH_TYPE_ABORT: return "Abort";
        case CRASH_TYPE_BUS_ERROR: return "Bus Error";
        case CRASH_TYPE_FLOATING_POINT: return "Floating Point Exception";
        case CRASH_TYPE_ILLEGAL_INSTRUCTION: return "Illegal Instruction";
        case CRASH_TYPE_ASSERTION: return "Assertion Failed";
        case CRASH_TYPE_OUT_OF_MEMORY: return "Out of Memory";
        case CRASH_TYPE_CUSTOM: return "Custom Crash";
        default: return "Unknown";
    }
}

static const char* signal_to_string(int sig) {
    switch (sig) {
        case SIGSEGV: return "SIGSEGV";
        case SIGABRT: return "SIGABRT";
        case SIGBUS: return "SIGBUS";
        case SIGFPE: return "SIGFPE";
        case SIGILL: return "SIGILL";
        case SIGTERM: return "SIGTERM";
        default: return "UNKNOWN";
    }
}

static bool create_crash_report_directory(void) {
    struct stat st = {0};
    if (stat(CRASH_REPORT_DIR, &st) == -1) {
        if (mkdir(CRASH_REPORT_DIR, 0755) != 0) {
            return false;
        }
    }
    return true;
}

static void populate_system_info(crash_info_t *crash_info) {
    if (!crash_info) return;
    
    crash_reporter_get_system_info(crash_info->system_info, sizeof(crash_info->system_info));
}

static void populate_thread_info(crash_info_t *crash_info) {
    if (!crash_info) return;
    
    pthread_getname_np(pthread_self(), crash_info->thread_name, sizeof(crash_info->thread_name));
}

static void update_crash_stats(crash_reporter_t *reporter, crash_type_t type) {
    if (!reporter) return;
    
    uint64_t current_time = clock_gettime_nsec_np(CLOCK_MONOTONIC);
    
    pthread_mutex_lock(&reporter->mutex);
    
    reporter->stats.total_crashes++;
    
    switch (type) {
        case CRASH_TYPE_SEGFAULT:
            reporter->stats.segfault_crashes++;
            break;
        case CRASH_TYPE_ABORT:
            reporter->stats.abort_crashes++;
            break;
        case CRASH_TYPE_BUS_ERROR:
            reporter->stats.bus_error_crashes++;
            break;
        case CRASH_TYPE_FLOATING_POINT:
            reporter->stats.floating_point_crashes++;
            break;
        case CRASH_TYPE_ILLEGAL_INSTRUCTION:
            reporter->stats.illegal_instruction_crashes++;
            break;
        case CRASH_TYPE_ASSERTION:
            reporter->stats.assertion_crashes++;
            break;
        case CRASH_TYPE_OUT_OF_MEMORY:
            reporter->stats.out_of_memory_crashes++;
            break;
        case CRASH_TYPE_CUSTOM:
            reporter->stats.custom_crashes++;
            break;
    }
    
    if (reporter->stats.first_crash_time == 0) {
        reporter->stats.first_crash_time = current_time;
    }
    reporter->stats.last_crash_time = current_time;
    
    pthread_mutex_unlock(&reporter->mutex);
}