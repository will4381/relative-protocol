#ifndef RP_DATAPLANE_H
#define RP_DATAPLANE_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    uint16_t api_version;
    uint16_t abi_version;
} rp_dp_version_t;

typedef struct {
    uint64_t packets_in;
    uint64_t packets_out;
    uint64_t bytes_in;
    uint64_t bytes_out;
} rp_dp_stats_t;

typedef void (*rp_dp_on_log_fn)(const char *message, void *user_ctx);
typedef void (*rp_dp_on_state_fn)(uint32_t state, void *user_ctx);

typedef struct {
    rp_dp_on_log_fn on_log;
    rp_dp_on_state_fn on_state;
} rp_dp_callbacks_t;

typedef struct rp_dp_handle rp_dp_handle_t;

/// Returns the dataplane API and ABI versions.
rp_dp_version_t rp_dp_get_version(void);

/// Creates a dataplane handle bound to a dedicated callback queue.
/// Callback contract:
/// - exactly one serial callback queue per handle
/// - FIFO callback ordering per handle
/// - callback payload pointers are valid only for callback scope
/// - control APIs must not be called reentrantly from callback context
rp_dp_handle_t *rp_dp_create(const char *config_json, const rp_dp_callbacks_t *callbacks, void *user_ctx);

/// Starts packet processing using the supplied TUN file descriptor.
int32_t rp_dp_start(rp_dp_handle_t *handle, int32_t tun_fd);

/// Stops packet processing for an active dataplane handle.
int32_t rp_dp_stop(rp_dp_handle_t *handle);

/// Destroys an existing dataplane handle.
void rp_dp_destroy(rp_dp_handle_t *handle);

/// Retrieves dataplane statistics.
int32_t rp_dp_get_stats(rp_dp_handle_t *handle, rp_dp_stats_t *out_stats);

#ifdef __cplusplus
}
#endif

#endif
