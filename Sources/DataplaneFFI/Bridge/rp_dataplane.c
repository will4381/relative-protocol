#include "rp_dataplane.h"

#include <errno.h>
#include <fcntl.h>
#include <stddef.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <time.h>
#include <unistd.h>

#define RP_DP_API_VERSION 1
#define RP_DP_ABI_VERSION 1
#define RP_DP_STATE_CREATED 0
#define RP_DP_STATE_RUNNING 1
#define RP_DP_STATE_STOPPED 2
#define RP_DP_MAX_CALLBACK_QUEUE_DEPTH 4096

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

static pthread_key_t rp_dp_callback_queue_key;
static pthread_key_t rp_dp_worker_queue_key;
static pthread_once_t rp_dp_thread_keys_once = PTHREAD_ONCE_INIT;
static pthread_mutex_t rp_dp_global_lock = PTHREAD_MUTEX_INITIALIZER;
static struct rp_dp_handle *rp_dp_active_handle;
static uint32_t rp_dp_tcp_isn_counter;

struct rp_dp_callback_task {
    uint8_t kind;
    uint32_t state;
    char *message;
    struct rp_dp_callback_task *next;
};

struct rp_dp_callback_queue {
    pthread_t thread;
    pthread_mutex_t lock;
    pthread_cond_t cond;
    struct rp_dp_handle *handle;
    struct rp_dp_callback_task *head;
    struct rp_dp_callback_task *tail;
    size_t depth;
    uint64_t dropped;
    uint8_t running;
    uint8_t stopped;
};

struct rp_dp_handle {
    struct rp_dp_callback_queue callback_queue;
    pthread_t worker_thread;
    pthread_mutex_t startup_lock;
    pthread_cond_t startup_cond;
    rp_dp_callbacks_t callbacks;
    void *user_ctx;
    rp_dp_stats_t stats;
    char *config_json;
    size_t config_len;
    int32_t tun_fd;
    uint8_t worker_joinable;
    uint8_t startup_signaled;
    uint8_t started;
    uint8_t stopping;
    uint8_t ready;
    uint8_t exited;
    int32_t exit_code;
};

enum {
    RP_DP_CALLBACK_LOG = 1,
    RP_DP_CALLBACK_STATE = 2
};

static void rp_dp_init_thread_keys(void)
{
    (void)pthread_key_create(&rp_dp_callback_queue_key, NULL);
    (void)pthread_key_create(&rp_dp_worker_queue_key, NULL);
}

static void rp_dp_callback_task_destroy(struct rp_dp_callback_task *task)
{
    if (task == NULL) {
        return;
    }
    free(task->message);
    free(task);
}

static void *rp_dp_callback_queue_main(void *ctx)
{
    struct rp_dp_callback_queue *queue = (struct rp_dp_callback_queue *)ctx;
    struct rp_dp_handle *handle = queue->handle;

    pthread_once(&rp_dp_thread_keys_once, rp_dp_init_thread_keys);
    pthread_setspecific(rp_dp_callback_queue_key, handle);

    for (;;) {
        pthread_mutex_lock(&queue->lock);
        while (queue->head == NULL && queue->stopped == 0) {
            pthread_cond_wait(&queue->cond, &queue->lock);
        }
        if (queue->head == NULL && queue->stopped != 0) {
            pthread_mutex_unlock(&queue->lock);
            break;
        }
        struct rp_dp_callback_task *task = queue->head;
        queue->head = task->next;
        if (queue->head == NULL) {
            queue->tail = NULL;
        }
        if (queue->depth > 0) {
            queue->depth--;
        }
        pthread_mutex_unlock(&queue->lock);

        switch (task->kind) {
        case RP_DP_CALLBACK_LOG:
            if (handle->callbacks.on_log != NULL && task->message != NULL) {
                handle->callbacks.on_log(task->message, handle->user_ctx);
            }
            break;
        case RP_DP_CALLBACK_STATE:
            if (handle->callbacks.on_state != NULL) {
                handle->callbacks.on_state(task->state, handle->user_ctx);
            }
            break;
        default:
            break;
        }

        rp_dp_callback_task_destroy(task);
    }

    pthread_setspecific(rp_dp_callback_queue_key, NULL);
    return NULL;
}

static int rp_dp_callback_queue_start(struct rp_dp_handle *handle)
{
    struct rp_dp_callback_queue *queue = &handle->callback_queue;
    memset(queue, 0, sizeof(*queue));
    queue->handle = handle;
    if (pthread_mutex_init(&queue->lock, NULL) != 0) {
        return -1;
    }
    if (pthread_cond_init(&queue->cond, NULL) != 0) {
        pthread_mutex_destroy(&queue->lock);
        return -1;
    }
    if (pthread_create(&queue->thread, NULL, rp_dp_callback_queue_main, queue) != 0) {
        pthread_cond_destroy(&queue->cond);
        pthread_mutex_destroy(&queue->lock);
        return -1;
    }
    queue->running = 1;
    return 0;
}

static int rp_dp_callback_queue_enqueue(struct rp_dp_handle *handle,
                                        struct rp_dp_callback_task *task)
{
    struct rp_dp_callback_queue *queue;

    if (handle == NULL || task == NULL) {
        return -1;
    }

    queue = &handle->callback_queue;
    pthread_mutex_lock(&queue->lock);
    if (queue->stopped != 0) {
        pthread_mutex_unlock(&queue->lock);
        return -1;
    }
    if (queue->depth >= RP_DP_MAX_CALLBACK_QUEUE_DEPTH) {
        queue->dropped++;
        pthread_mutex_unlock(&queue->lock);
        return -2;
    }
    task->next = NULL;
    if (queue->tail != NULL) {
        queue->tail->next = task;
    } else {
        queue->head = task;
    }
    queue->tail = task;
    queue->depth++;
    pthread_cond_signal(&queue->cond);
    pthread_mutex_unlock(&queue->lock);
    return 0;
}

static void *rp_dp_destroy_async_main(void *ctx)
{
    struct rp_dp_handle *handle = (struct rp_dp_handle *)ctx;
    (void)rp_dp_destroy(handle);
    return NULL;
}

static void rp_dp_callback_queue_stop_and_join(struct rp_dp_handle *handle)
{
    struct rp_dp_callback_queue *queue;

    if (handle == NULL) {
        return;
    }
    queue = &handle->callback_queue;
    if (queue->running == 0) {
        return;
    }

    pthread_mutex_lock(&queue->lock);
    queue->stopped = 1;
    pthread_cond_signal(&queue->cond);
    pthread_mutex_unlock(&queue->lock);

    if (pthread_getspecific(rp_dp_callback_queue_key) != handle) {
        pthread_join(queue->thread, NULL);
    }

    queue->running = 0;
    pthread_cond_destroy(&queue->cond);
    pthread_mutex_destroy(&queue->lock);
}

static void rp_dp_signal_startup(struct rp_dp_handle *handle)
{
    if (handle == NULL) {
        return;
    }
    pthread_mutex_lock(&handle->startup_lock);
    handle->startup_signaled = 1;
    pthread_cond_broadcast(&handle->startup_cond);
    pthread_mutex_unlock(&handle->startup_lock);
}

static int rp_dp_wait_startup(struct rp_dp_handle *handle, int timeout_seconds)
{
    struct timespec deadline;
    int result = 0;

    if (clock_gettime(CLOCK_REALTIME, &deadline) != 0) {
        return -1;
    }
    deadline.tv_sec += timeout_seconds;

    pthread_mutex_lock(&handle->startup_lock);
    while (handle->startup_signaled == 0 && result == 0) {
        result = pthread_cond_timedwait(
            &handle->startup_cond,
            &handle->startup_lock,
            &deadline);
    }
    pthread_mutex_unlock(&handle->startup_lock);
    return result == 0 ? 0 : -1;
}

static int32_t rp_dp_reentrant_call_guard(void)
{
    pthread_once(&rp_dp_thread_keys_once, rp_dp_init_thread_keys);
    if (pthread_getspecific(rp_dp_callback_queue_key) != NULL) {
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

    struct rp_dp_callback_task *task =
        (struct rp_dp_callback_task *)calloc(1, sizeof(struct rp_dp_callback_task));
    if (task == NULL) {
        free(payload);
        return;
    }
    task->kind = RP_DP_CALLBACK_LOG;
    task->message = payload;
    if (rp_dp_callback_queue_enqueue(handle, task) != 0) {
        rp_dp_callback_task_destroy(task);
    }
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

    struct rp_dp_callback_task *task =
        (struct rp_dp_callback_task *)calloc(1, sizeof(struct rp_dp_callback_task));
    if (task == NULL) {
        return;
    }
    task->kind = RP_DP_CALLBACK_STATE;
    task->state = state;
    if (rp_dp_callback_queue_enqueue(handle, task) != 0) {
        rp_dp_callback_task_destroy(task);
    }
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
    pthread_mutex_lock(&rp_dp_global_lock);
    handle->stats.packets_in = (uint64_t)rx_packets;
    handle->stats.bytes_in = (uint64_t)rx_bytes;
    handle->stats.packets_out = (uint64_t)tx_packets;
    handle->stats.bytes_out = (uint64_t)tx_bytes;
    pthread_mutex_unlock(&rp_dp_global_lock);
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
    pthread_t worker_thread;
    uint8_t should_join;

    if (handle == NULL) {
        return;
    }
    pthread_once(&rp_dp_thread_keys_once, rp_dp_init_thread_keys);
    if (pthread_getspecific(rp_dp_worker_queue_key) == handle) {
        return;
    }

    pthread_mutex_lock(&rp_dp_global_lock);
    should_join = handle->worker_joinable;
    worker_thread = handle->worker_thread;
    if (should_join != 0) {
        handle->worker_joinable = 0;
    }
    pthread_mutex_unlock(&rp_dp_global_lock);

    if (should_join != 0) {
        pthread_join(worker_thread, NULL);
    }
}

void rp_dp_hev_notify_ready(void)
{
    int should_stop = 0;
    struct rp_dp_handle *handle = NULL;
    int should_signal = 0;

    pthread_mutex_lock(&rp_dp_global_lock);
    handle = rp_dp_active_handle;
    if (handle != NULL) {
        handle->ready = 1;
        should_stop = handle->stopping != 0;
        should_signal = 1;
    }
    pthread_mutex_unlock(&rp_dp_global_lock);

    if (should_signal != 0) {
        rp_dp_signal_startup(handle);
    }
    if (handle != NULL) {
        rp_dp_dispatch_state(handle, RP_DP_STATE_RUNNING);
        rp_dp_dispatch_log(handle, RP_DP_READY_MSG);
    }
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

static void *rp_dp_worker_main(void *ctx)
{
    struct rp_dp_handle *handle = (struct rp_dp_handle *)ctx;

    pthread_once(&rp_dp_thread_keys_once, rp_dp_init_thread_keys);
    pthread_setspecific(rp_dp_worker_queue_key, handle);

    /*
     * Do not redirect process-wide stderr inside the extension process.
     * Blocking global file descriptors is a liveness risk under load.
     */
    int32_t worker_tun_fd;
    const char *worker_config_json;
    size_t worker_config_len;
    pthread_mutex_lock(&rp_dp_global_lock);
    worker_tun_fd = handle->tun_fd;
    worker_config_json = handle->config_json;
    worker_config_len = handle->config_len;
    pthread_mutex_unlock(&rp_dp_global_lock);

    int result = hev_socks5_tunnel_main_from_str(
        (const unsigned char *)worker_config_json,
        (unsigned int)worker_config_len,
        worker_tun_fd);

    rp_dp_refresh_stats(handle);
    pthread_mutex_lock(&rp_dp_global_lock);
    handle->exit_code = result;
    handle->exited = 1;
    handle->started = 0;
    int should_dispatch_stopped = !handle->stopping;
    pthread_mutex_unlock(&rp_dp_global_lock);

    if (result == 0) {
        rp_dp_dispatch_logf(handle, "%s exit_code=%d", RP_DP_EXITED_MSG,
                            result);
    } else {
        rp_dp_dispatch_logf(handle, "%s exit_code=%d",
                            RP_DP_EXITED_ERROR_MSG, result);
    }

    if (should_dispatch_stopped) {
        rp_dp_dispatch_state(handle, RP_DP_STATE_STOPPED);
    }
    rp_dp_clear_active_handle_if_current(handle);
    rp_dp_signal_startup(handle);

    pthread_setspecific(rp_dp_worker_queue_key, NULL);
    return NULL;
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

    pthread_once(&rp_dp_thread_keys_once, rp_dp_init_thread_keys);
    if (pthread_mutex_init(&handle->startup_lock, NULL) != 0) {
        free(handle);
        return NULL;
    }
    if (pthread_cond_init(&handle->startup_cond, NULL) != 0) {
        pthread_mutex_destroy(&handle->startup_lock);
        free(handle);
        return NULL;
    }
    if (rp_dp_callback_queue_start(handle) != 0) {
        pthread_cond_destroy(&handle->startup_cond);
        pthread_mutex_destroy(&handle->startup_lock);
        free(handle);
        return NULL;
    }

    handle->user_ctx = user_ctx;
    handle->worker_joinable = 0;
    handle->startup_signaled = 0;
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
    pthread_mutex_lock(&rp_dp_global_lock);
    if (handle->started != 0) {
        uint8_t ready = handle->ready;
        pthread_mutex_unlock(&rp_dp_global_lock);
        return ready != 0 ? 0 : -6;
    }
    if (rp_dp_active_handle != NULL && rp_dp_active_handle != handle) {
        pthread_mutex_unlock(&rp_dp_global_lock);
        return -5;
    }
    rp_dp_active_handle = handle;
    handle->tun_fd = tun_fd;
    handle->started = 1;
    handle->stopping = 0;
    handle->ready = 0;
    handle->exited = 0;
    handle->exit_code = 0;
    handle->startup_signaled = 0;
    pthread_mutex_unlock(&rp_dp_global_lock);

    if (rp_dp_is_deterministic_local_mode(handle) && tun_fd == 0) {
        pthread_mutex_lock(&rp_dp_global_lock);
        handle->ready = 1;
        pthread_mutex_unlock(&rp_dp_global_lock);
        rp_dp_dispatch_state(handle, RP_DP_STATE_RUNNING);
        rp_dp_dispatch_log(handle, RP_DP_RUNNING_MSG);
        return 0;
    }

    if (pthread_create(&handle->worker_thread, NULL, rp_dp_worker_main, handle) != 0) {
        pthread_mutex_lock(&rp_dp_global_lock);
        handle->started = 0;
        handle->stopping = 0;
        handle->ready = 0;
        pthread_mutex_unlock(&rp_dp_global_lock);
        rp_dp_clear_active_handle_if_current(handle);
        rp_dp_dispatch_log(handle, "dataplane-worker-create-failed");
        return -8;
    }

    pthread_mutex_lock(&rp_dp_global_lock);
    handle->worker_joinable = 1;
    pthread_mutex_unlock(&rp_dp_global_lock);

    int wait_result = rp_dp_wait_startup(handle, 5);
    if (wait_result != 0) {
        pthread_mutex_lock(&rp_dp_global_lock);
        handle->stopping = 1;
        pthread_mutex_unlock(&rp_dp_global_lock);
        hev_socks5_tunnel_quit();
        rp_dp_wait_worker_if_needed(handle);
        pthread_mutex_lock(&rp_dp_global_lock);
        handle->started = 0;
        handle->stopping = 0;
        handle->ready = 0;
        handle->exited = 1;
        handle->exit_code = -6;
        pthread_mutex_unlock(&rp_dp_global_lock);
        rp_dp_clear_active_handle_if_current(handle);
        rp_dp_dispatch_log(handle, "dataplane-start-timeout");
        return -6;
    }
    pthread_mutex_lock(&rp_dp_global_lock);
    uint8_t ready = handle->ready;
    int32_t exit_code = handle->exit_code;
    pthread_mutex_unlock(&rp_dp_global_lock);
    if (ready != 0) {
        rp_dp_dispatch_log(handle, RP_DP_RUNNING_MSG);
        return 0;
    }

    rp_dp_clear_active_handle_if_current(handle);
    return exit_code == 0 ? -7 : exit_code;
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
    pthread_mutex_lock(&rp_dp_global_lock);
    uint8_t started = handle->started;
    int32_t tun_fd = handle->tun_fd;
    pthread_mutex_unlock(&rp_dp_global_lock);
    if (started == 0) {
        return 0;
    }

    if (rp_dp_is_deterministic_local_mode(handle) && tun_fd == 0) {
        pthread_mutex_lock(&rp_dp_global_lock);
        handle->started = 0;
        handle->ready = 0;
        pthread_mutex_unlock(&rp_dp_global_lock);
        rp_dp_clear_active_handle_if_current(handle);
        rp_dp_dispatch_state(handle, RP_DP_STATE_STOPPED);
        rp_dp_dispatch_log(handle, RP_DP_STOPPED_MSG);
        return 0;
    }

    pthread_mutex_lock(&rp_dp_global_lock);
    handle->stopping = 1;
    pthread_mutex_unlock(&rp_dp_global_lock);
    hev_socks5_tunnel_quit();
    rp_dp_wait_worker_if_needed(handle);
    pthread_mutex_lock(&rp_dp_global_lock);
    handle->started = 0;
    handle->stopping = 0;
    handle->ready = 0;
    pthread_mutex_unlock(&rp_dp_global_lock);
    rp_dp_clear_active_handle_if_current(handle);

    rp_dp_refresh_stats(handle);
    rp_dp_dispatch_state(handle, RP_DP_STATE_STOPPED);
    rp_dp_dispatch_log(handle, RP_DP_STOPPED_MSG);
    return 0;
}

int32_t rp_dp_destroy(rp_dp_handle_t *opaque_handle)
{
    struct rp_dp_handle *handle = (struct rp_dp_handle *)opaque_handle;
    if (handle == NULL) {
        return 0;
    }
    if (rp_dp_reentrant_call_guard() != 0) {
        pthread_t cleanup_thread;
        if (pthread_create(&cleanup_thread, NULL, rp_dp_destroy_async_main, handle) != 0) {
            return -2;
        }
        pthread_detach(cleanup_thread);
        return 1;
    }

    pthread_mutex_lock(&rp_dp_global_lock);
    uint8_t started = handle->started;
    pthread_mutex_unlock(&rp_dp_global_lock);
    if (started != 0) {
        (void)rp_dp_stop(handle);
    }

    rp_dp_wait_worker_if_needed(handle);
    rp_dp_callback_queue_stop_and_join(handle);
    pthread_cond_destroy(&handle->startup_cond);
    pthread_mutex_destroy(&handle->startup_lock);

    if (handle->config_json != NULL) {
        free(handle->config_json);
        handle->config_json = NULL;
        handle->config_len = 0;
    }

    free(handle);
    return 0;
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
    pthread_mutex_lock(&rp_dp_global_lock);
    *out_stats = handle->stats;
    pthread_mutex_unlock(&rp_dp_global_lock);
    return 0;
}

uint32_t lwip_port_tcp_isn(const void *local_ip,
                           uint16_t local_port,
                           const void *remote_ip,
                           uint16_t remote_port)
{
    (void)local_ip;
    (void)remote_ip;

    pthread_mutex_lock(&rp_dp_global_lock);
    rp_dp_tcp_isn_counter += 64000u + (arc4random() & 0xffu);
    uint32_t counter = rp_dp_tcp_isn_counter;
    pthread_mutex_unlock(&rp_dp_global_lock);

    return arc4random() ^ counter ^ ((uint32_t)local_port << 16) ^ (uint32_t)remote_port;
}
