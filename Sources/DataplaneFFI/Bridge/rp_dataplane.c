#include "rp_dataplane.h"

#include <dispatch/dispatch.h>
#include <errno.h>
#include <fcntl.h>
#include <stddef.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <unistd.h>

#define RP_DP_API_VERSION 1
#define RP_DP_ABI_VERSION 1
#define RP_DP_STATE_CREATED 0
#define RP_DP_STATE_RUNNING 1
#define RP_DP_STATE_STOPPED 2

static const char *RP_DP_CREATED_MSG = "dataplane-created";
static const char *RP_DP_RUNNING_MSG = "dataplane-running";
static const char *RP_DP_STOPPED_MSG = "dataplane-stopped";
static const char *RP_DP_EXITED_MSG = "dataplane-exited";
static const char *RP_DP_EXITED_ERROR_MSG = "dataplane-exited-error";
static const char *RP_DP_READY_MSG = "dataplane-ready";

/*
 * Vendored symbols exported by HevSocks5Tunnel. We declare them here to avoid
 * patching vendored headers.
 */
extern int hev_socks5_tunnel_main_from_str(const unsigned char *config_str,
                                           unsigned int config_len,
                                           int tun_fd);
extern void hev_socks5_tunnel_quit(void);
extern void hev_socks5_tunnel_stats(size_t *tx_packets, size_t *tx_bytes,
                                    size_t *rx_packets, size_t *rx_bytes);

static uint8_t rp_dp_callback_queue_key;
static uint8_t rp_dp_worker_queue_key;
static pthread_mutex_t rp_dp_global_lock = PTHREAD_MUTEX_INITIALIZER;
static struct rp_dp_handle *rp_dp_active_handle;

struct rp_dp_handle {
    dispatch_queue_t callback_queue;
    dispatch_queue_t worker_queue;
    dispatch_semaphore_t startup_semaphore;
    rp_dp_callbacks_t callbacks;
    void *user_ctx;
    rp_dp_stats_t stats;
    char *config_json;
    size_t config_len;
    int32_t tun_fd;
    uint8_t started;
    uint8_t stopping;
    uint8_t ready;
    uint8_t exited;
    int32_t exit_code;
};

static int32_t rp_dp_reentrant_call_guard(void)
{
    if (dispatch_get_specific(&rp_dp_callback_queue_key) != NULL) {
        return -2;
    }
    return 0;
}

static void rp_dp_dispatch_log(struct rp_dp_handle *handle, const char *message)
{
    if (handle == NULL || handle->callbacks.on_log == NULL || message == NULL) {
        return;
    }

    char *payload = strdup(message);
    if (payload == NULL) {
        return;
    }

    dispatch_async(handle->callback_queue, ^{
        handle->callbacks.on_log(payload, handle->user_ctx);
        free(payload);
    });
}

static void rp_dp_dispatch_logf(struct rp_dp_handle *handle, const char *format,
                                ...)
{
    char stack_buffer[512];
    int length;
    va_list args;

    if (handle == NULL || format == NULL) {
        return;
    }

    va_start(args, format);
    length = vsnprintf(stack_buffer, sizeof(stack_buffer), format, args);
    va_end(args);

    if (length < 0) {
        return;
    }

    if ((size_t)length < sizeof(stack_buffer)) {
        rp_dp_dispatch_log(handle, stack_buffer);
        return;
    }

    char *heap_buffer = (char *)calloc((size_t)length + 1u, sizeof(char));
    if (heap_buffer == NULL) {
        return;
    }

    va_start(args, format);
    (void)vsnprintf(heap_buffer, (size_t)length + 1u, format, args);
    va_end(args);
    rp_dp_dispatch_log(handle, heap_buffer);
    free(heap_buffer);
}

static void rp_dp_dispatch_state(struct rp_dp_handle *handle, uint32_t state)
{
    if (handle == NULL || handle->callbacks.on_state == NULL) {
        return;
    }

    dispatch_async(handle->callback_queue, ^{
        handle->callbacks.on_state(state, handle->user_ctx);
    });
}

static void rp_dp_refresh_stats(struct rp_dp_handle *handle)
{
    size_t tx_packets = 0;
    size_t tx_bytes = 0;
    size_t rx_packets = 0;
    size_t rx_bytes = 0;

    if (handle == NULL) {
        return;
    }

    hev_socks5_tunnel_stats(&tx_packets, &tx_bytes, &rx_packets, &rx_bytes);
    handle->stats.packets_in = (uint64_t)rx_packets;
    handle->stats.bytes_in = (uint64_t)rx_bytes;
    handle->stats.packets_out = (uint64_t)tx_packets;
    handle->stats.bytes_out = (uint64_t)tx_bytes;
}

static int rp_dp_is_deterministic_local_mode(struct rp_dp_handle *handle)
{
    if (handle == NULL || handle->config_json == NULL) {
        return 0;
    }
    return strstr(handle->config_json, "deterministic-local") != NULL;
}

static void rp_dp_wait_worker_if_needed(struct rp_dp_handle *handle)
{
    if (handle == NULL || handle->worker_queue == NULL) {
        return;
    }
    if (dispatch_get_specific(&rp_dp_worker_queue_key) != NULL) {
        return;
    }
    dispatch_sync(handle->worker_queue, ^{
    });
}

void rp_dp_hev_notify_ready(void)
{
    int should_stop = 0;

    pthread_mutex_lock(&rp_dp_global_lock);
    struct rp_dp_handle *handle = rp_dp_active_handle;
    if (handle != NULL) {
        handle->ready = 1;
        should_stop = handle->stopping != 0;
        if (handle->startup_semaphore != NULL) {
            dispatch_semaphore_signal(handle->startup_semaphore);
        }
        rp_dp_dispatch_state(handle, RP_DP_STATE_RUNNING);
        rp_dp_dispatch_log(handle, RP_DP_READY_MSG);
    }
    pthread_mutex_unlock(&rp_dp_global_lock);

    if (should_stop) {
        hev_socks5_tunnel_quit();
    }
}

static void rp_dp_clear_active_handle_if_current(struct rp_dp_handle *handle)
{
    pthread_mutex_lock(&rp_dp_global_lock);
    if (rp_dp_active_handle == handle) {
        rp_dp_active_handle = NULL;
    }
    pthread_mutex_unlock(&rp_dp_global_lock);
}

rp_dp_version_t rp_dp_get_version(void)
{
    rp_dp_version_t version;
    version.api_version = RP_DP_API_VERSION;
    version.abi_version = RP_DP_ABI_VERSION;
    return version;
}

rp_dp_handle_t *rp_dp_create(const char *config_json,
                             const rp_dp_callbacks_t *callbacks,
                             void *user_ctx)
{
    struct rp_dp_handle *handle =
        (struct rp_dp_handle *)calloc(1, sizeof(struct rp_dp_handle));
    if (handle == NULL) {
        return NULL;
    }

    if (callbacks != NULL) {
        handle->callbacks = *callbacks;
    } else {
        memset(&handle->callbacks, 0, sizeof(rp_dp_callbacks_t));
    }

    handle->callback_queue = dispatch_queue_create(
        "com.vpnbridge.dataplane.callback", DISPATCH_QUEUE_SERIAL);
    handle->worker_queue = dispatch_queue_create(
        "com.vpnbridge.dataplane.worker", DISPATCH_QUEUE_SERIAL);
    handle->startup_semaphore = dispatch_semaphore_create(0);
    dispatch_queue_set_specific(handle->callback_queue, &rp_dp_callback_queue_key,
                                handle, NULL);
    dispatch_queue_set_specific(handle->worker_queue, &rp_dp_worker_queue_key,
                                handle, NULL);

    handle->user_ctx = user_ctx;
    handle->started = 0;
    handle->stopping = 0;
    handle->ready = 0;
    handle->exited = 0;
    handle->exit_code = 0;
    handle->tun_fd = -1;

    if (config_json == NULL || config_json[0] == '\0') {
        handle->config_json = strdup("{}");
    } else {
        handle->config_json = strdup(config_json);
    }
    if (handle->config_json == NULL) {
        rp_dp_destroy(handle);
        return NULL;
    }
    handle->config_len = strlen(handle->config_json);

    rp_dp_dispatch_state(handle, RP_DP_STATE_CREATED);
    rp_dp_dispatch_log(handle, RP_DP_CREATED_MSG);
    return handle;
}

int32_t rp_dp_start(rp_dp_handle_t *opaque_handle, int32_t tun_fd)
{
    struct rp_dp_handle *handle = (struct rp_dp_handle *)opaque_handle;
    if (handle == NULL) {
        return -1;
    }
    if (rp_dp_reentrant_call_guard() != 0) {
        return -2;
    }
    if (tun_fd < 0) {
        return -3;
    }
    if (handle->config_json == NULL || handle->config_len == 0) {
        return -4;
    }
    if (handle->started != 0) {
        return 0;
    }

    pthread_mutex_lock(&rp_dp_global_lock);
    if (rp_dp_active_handle != NULL && rp_dp_active_handle != handle) {
        pthread_mutex_unlock(&rp_dp_global_lock);
        return -5;
    }
    rp_dp_active_handle = handle;
    pthread_mutex_unlock(&rp_dp_global_lock);

    handle->tun_fd = tun_fd;
    handle->started = 1;
    handle->stopping = 0;
    handle->ready = 0;
    handle->exited = 0;
    handle->exit_code = 0;

    if (rp_dp_is_deterministic_local_mode(handle) && tun_fd == 0) {
        handle->ready = 1;
        rp_dp_dispatch_state(handle, RP_DP_STATE_RUNNING);
        rp_dp_dispatch_log(handle, RP_DP_RUNNING_MSG);
        return 0;
    }

    dispatch_async(handle->worker_queue, ^{
        /*
         * Do not redirect process-wide stderr inside the extension process.
         * Blocking global file descriptors is a liveness risk under load.
         */
        int result = hev_socks5_tunnel_main_from_str(
            (const unsigned char *)handle->config_json,
            (unsigned int)handle->config_len,
            handle->tun_fd);

        rp_dp_refresh_stats(handle);
        handle->exit_code = result;
        handle->exited = 1;
        handle->started = 0;

        if (result == 0) {
            rp_dp_dispatch_logf(handle, "%s exit_code=%d", RP_DP_EXITED_MSG,
                                result);
        } else {
            rp_dp_dispatch_logf(handle, "%s exit_code=%d",
                                RP_DP_EXITED_ERROR_MSG, result);
        }

        if (!handle->stopping) {
            rp_dp_dispatch_state(handle, RP_DP_STATE_STOPPED);
        }
        rp_dp_clear_active_handle_if_current(handle);
        if (handle->startup_semaphore != NULL) {
            dispatch_semaphore_signal(handle->startup_semaphore);
        }
    });

    intptr_t wait_result = dispatch_semaphore_wait(
        handle->startup_semaphore,
        dispatch_time(DISPATCH_TIME_NOW, 5LL * NSEC_PER_SEC));
    if (wait_result != 0) {
        handle->stopping = 1;
        rp_dp_clear_active_handle_if_current(handle);
        hev_socks5_tunnel_quit();
        rp_dp_dispatch_log(handle, "dataplane-start-timeout");
        return -6;
    }
    if (handle->ready != 0) {
        rp_dp_dispatch_log(handle, RP_DP_RUNNING_MSG);
        return 0;
    }

    rp_dp_clear_active_handle_if_current(handle);
    return handle->exit_code == 0 ? -7 : handle->exit_code;
}

int32_t rp_dp_stop(rp_dp_handle_t *opaque_handle)
{
    struct rp_dp_handle *handle = (struct rp_dp_handle *)opaque_handle;
    if (handle == NULL) {
        return -1;
    }
    if (rp_dp_reentrant_call_guard() != 0) {
        return -2;
    }
    if (handle->started == 0) {
        return 0;
    }

    if (rp_dp_is_deterministic_local_mode(handle) && handle->tun_fd == 0) {
        handle->started = 0;
        handle->ready = 0;
        rp_dp_clear_active_handle_if_current(handle);
        rp_dp_dispatch_state(handle, RP_DP_STATE_STOPPED);
        rp_dp_dispatch_log(handle, RP_DP_STOPPED_MSG);
        return 0;
    }

    handle->stopping = 1;
    hev_socks5_tunnel_quit();
    rp_dp_wait_worker_if_needed(handle);
    handle->started = 0;
    handle->stopping = 0;
    handle->ready = 0;
    rp_dp_clear_active_handle_if_current(handle);

    rp_dp_refresh_stats(handle);
    rp_dp_dispatch_state(handle, RP_DP_STATE_STOPPED);
    rp_dp_dispatch_log(handle, RP_DP_STOPPED_MSG);
    return 0;
}

void rp_dp_destroy(rp_dp_handle_t *opaque_handle)
{
    struct rp_dp_handle *handle = (struct rp_dp_handle *)opaque_handle;
    if (handle == NULL) {
        return;
    }

    if (handle->started != 0) {
        (void)rp_dp_stop(handle);
    }

    if (dispatch_get_specific(&rp_dp_callback_queue_key) == NULL) {
        dispatch_sync(handle->callback_queue, ^{
        });
    }
    rp_dp_wait_worker_if_needed(handle);

#if OS_OBJECT_USE_OBJC
    handle->callback_queue = NULL;
    handle->worker_queue = NULL;
    handle->startup_semaphore = NULL;
#else
    if (handle->callback_queue != NULL) {
        dispatch_release(handle->callback_queue);
        handle->callback_queue = NULL;
    }
    if (handle->worker_queue != NULL) {
        dispatch_release(handle->worker_queue);
        handle->worker_queue = NULL;
    }
    if (handle->startup_semaphore != NULL) {
        dispatch_release(handle->startup_semaphore);
        handle->startup_semaphore = NULL;
    }
#endif

    if (handle->config_json != NULL) {
        free(handle->config_json);
        handle->config_json = NULL;
        handle->config_len = 0;
    }

    free(handle);
}

int32_t rp_dp_get_stats(rp_dp_handle_t *opaque_handle, rp_dp_stats_t *out_stats)
{
    struct rp_dp_handle *handle = (struct rp_dp_handle *)opaque_handle;
    if (handle == NULL || out_stats == NULL) {
        return -1;
    }
    if (rp_dp_reentrant_call_guard() != 0) {
        return -2;
    }

    rp_dp_refresh_stats(handle);
    *out_stats = handle->stats;
    return 0;
}

/*
 * lwIP expects this symbol when its random macro is enabled.
 * We provide it in first-party bridge code to avoid patching vendored sources.
 */
uint32_t lwip_port_rand(void)
{
    return (uint32_t)rand();
}
