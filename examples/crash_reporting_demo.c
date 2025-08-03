/**
 * Crash Reporting Demo
 * 
 * This demonstrates the comprehensive crash reporting system
 * integrated into the VPN framework.
 */

#include "api/relative_vpn.h"
#include "crash/reporter.h"
#include "core/logging.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>

static void demo_crash_callback(const crash_info_t *crash_info, void *user_data) {
    printf("=== CRASH DETECTED ===\n");
    printf("Type: %d\n", crash_info->type);
    printf("Signal: %d\n", crash_info->signal_number);
    printf("Process ID: %u\n", crash_info->process_id);
    printf("Thread ID: %u\n", crash_info->thread_id);
    printf("Timestamp: %llu ns\n", crash_info->timestamp_ns);
    
    if (crash_info->custom_data[0]) {
        printf("Custom Data: %s\n", crash_info->custom_data);
    }
    
    if (crash_info->stack_trace_count > 0) {
        printf("Stack Trace (%zu frames):\n", crash_info->stack_trace_count);
        for (size_t i = 0; i < crash_info->stack_trace_count && i < 10; i++) {
            printf("  #%zu: %p\n", i, crash_info->stack_trace[i]);
        }
    }
    
    printf("========================\n");
}

static void demonstrate_crash_reporting(void) {
    printf("=== Crash Reporting System Demo ===\n\n");
    
    // Create and initialize crash reporter
    crash_reporter_t *reporter = crash_reporter_create();
    if (!reporter) {
        printf("ERROR: Failed to create crash reporter\n");
        return;
    }
    
    printf("1. Initializing crash reporter...\n");
    crash_reporter_flags_t flags = CRASH_REPORTER_ENABLE_STACK_TRACES |
                                  CRASH_REPORTER_ENABLE_SYSTEM_INFO |
                                  CRASH_REPORTER_ENABLE_THREAD_INFO;
    
    if (!crash_reporter_initialize(reporter, flags)) {
        printf("ERROR: Failed to initialize crash reporter\n");
        crash_reporter_destroy(reporter);
        return;
    }
    
    // Set version info and callback
    crash_reporter_set_version_info(reporter, "1.0.0", "demo-build");
    crash_reporter_set_callback(reporter, demo_crash_callback, NULL);
    crash_reporter_set_custom_data(reporter, "demo.mode", "testing");
    crash_reporter_set_custom_data(reporter, "demo.feature", "crash_reporting");
    
    printf("2. Enabling crash monitoring...\n");
    if (!crash_reporter_enable(reporter)) {
        printf("ERROR: Failed to enable crash reporter\n");
        crash_reporter_destroy(reporter);
        return;
    }
    
    printf("3. Demonstrating different crash types:\n\n");
    
    // Demonstrate custom crash reporting
    printf("   a) Custom error report:\n");
    crash_reporter_report_crash(reporter, CRASH_TYPE_CUSTOM, 
                               "Demonstration of custom crash reporting");
    sleep(1);
    
    // Demonstrate assertion failure
    printf("   b) Assertion failure report:\n");
    crash_reporter_report_assertion(reporter, "demo_condition != NULL", __FILE__, __LINE__);
    sleep(1);
    
    // Demonstrate out of memory report
    printf("   c) Out of memory report:\n");
    crash_reporter_report_crash(reporter, CRASH_TYPE_OUT_OF_MEMORY, 
                               "Simulated memory allocation failure");
    sleep(1);
    
    // Get and display crash statistics
    printf("\n4. Crash Statistics:\n");
    crash_stats_t stats;
    crash_reporter_get_stats(reporter, &stats);
    
    printf("   Total crashes: %u\n", stats.total_crashes);
    printf("   Custom crashes: %u\n", stats.custom_crashes);
    printf("   Assertion failures: %u\n", stats.assertion_crashes);
    printf("   Out of memory crashes: %u\n", stats.out_of_memory_crashes);
    printf("   First crash time: %llu ns\n", stats.first_crash_time);
    printf("   Last crash time: %llu ns\n", stats.last_crash_time);
    printf("   Crash rate: %.2f crashes/hour\n", stats.crash_rate_per_hour);
    
    printf("\n5. System Information:\n");
    char system_info[1024];
    if (crash_reporter_get_system_info(system_info, sizeof(system_info))) {
        printf("%s\n", system_info);
    }
    
    printf("\n6. Memory Information:\n");
    char memory_info[512];
    if (crash_reporter_get_memory_info(memory_info, sizeof(memory_info))) {
        printf("%s\n", memory_info);
    }
    
    printf("\n7. Thread Information:\n");
    char thread_info[256];
    if (crash_reporter_get_thread_info(thread_info, sizeof(thread_info))) {
        printf("%s\n", thread_info);
    }
    
    // Demonstrate VPN integration
    printf("\n8. VPN Integration Demo:\n");
    
    vpn_config_t config = {
        .utun_name = "utun2",
        .mtu = 1500,
        .tunnel_mtu = 1400,
        .ipv4_enabled = true,
        .ipv6_enabled = false,
        .enable_nat64 = false,
        .enable_dns_leak_protection = true,
        .enable_ipv6_leak_protection = true,
        .enable_kill_switch = true,
        .enable_webrtc_leak_protection = true,
        .dns_cache_size = 1000,
        .metrics_buffer_size = 10000,
        .reachability_monitoring = true,
        .log_level = "INFO",
        .dns_server_count = 1
    };
    
    config.dns_servers[0] = 0x08080808; // 8.8.8.8
    
    printf("   Starting VPN with crash reporting enabled...\n");
    vpn_result_t result = vpn_start_comprehensive(&config);
    
    if (result.status == VPN_SUCCESS) {
        printf("   VPN started successfully with handle: %p\n", result.handle);
        
        // Demonstrate custom error reporting through VPN API
        printf("   Reporting custom error through VPN API...\n");
        vpn_report_custom_error_comprehensive(result.handle, 
                                            "Demonstration error from VPN API");
        
        // Get crash stats through VPN API
        crash_stats_t vpn_stats;
        if (vpn_get_crash_stats_comprehensive(result.handle, &vpn_stats)) {
            printf("   VPN crash stats - Total crashes: %u\n", vpn_stats.total_crashes);
        }
        
        // Stop VPN
        printf("   Stopping VPN...\n");
        vpn_stop_comprehensive(result.handle);
    } else {
        printf("   VPN failed to start (status: %d)\n", result.status);
    }
    
    // Cleanup
    printf("\n9. Cleaning up crash reporter...\n");
    crash_reporter_disable(reporter);
    crash_reporter_destroy(reporter);
    
    printf("\n=== Demo Complete ===\n");
    printf("Check /tmp/vpn_crashes/ for saved crash reports\n");
}

int main(void) {
    // Initialize logging
    log_init("DEBUG");
    
    printf("VPN Framework - Crash Reporting System Demo\n");
    printf("===========================================\n\n");
    
    demonstrate_crash_reporting();
    
    return 0;
}