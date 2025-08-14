#include <dispatch/dispatch.h>
#include <pthread.h>
#include <stdatomic.h>
#include "lwip/opt.h"
#include "lwip/sys.h"

// Minimal NO_SYS glue: we only need time and critical section stubs.

u32_t sys_now(void) {
    // Milliseconds since boot
    return (u32_t)(clock_gettime_nsec_np(CLOCK_MONOTONIC) / 1000000ULL);
}

u32_t sys_jiffies(void) {
    return sys_now();
}

sys_prot_t sys_arch_protect(void) {
    // Rely on lwIP being called on a single queue in our port; return dummy
    return 0;
}

void sys_arch_unprotect(sys_prot_t pval) {
    (void)pval;
}


