#ifndef ENGINE_BRIDGE_H
#define ENGINE_BRIDGE_H

#pragma once

#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

#define DEFAULT_MTU 1280

#define RING_CAPACITY 1024

#define MAX_EMIT_BATCH 64

/**
 * Opaque engine handle shared with Swift/ObjC.
 */
typedef struct BridgeEngine BridgeEngine;

/**
 * Mirror of the `BridgeConfig` struct defined in `include/bridge.h`.
 */
typedef struct BridgeConfig {
  uint32_t mtu;
  uint32_t packet_pool_bytes;
  uint32_t per_flow_bytes;
} BridgeConfig;

typedef void (*EmitPacketsFn)(const uint8_t *const *packets,
                              const size_t *sizes,
                              const uint32_t *protocols,
                              size_t count,
                              void *context);

typedef void (*DialFn)(const int8_t *host, uint16_t port, uint64_t handle, void *context);

typedef void (*SendFn)(uint64_t handle, const uint8_t *payload, size_t length, void *context);

typedef void (*CloseFn)(uint64_t handle, const int8_t *message, void *context);

typedef void (*RecordDnsFn)(const int8_t *host,
                            const int8_t *const *addresses,
                            size_t count,
                            uint32_t ttl_seconds,
                            void *context);

/**
 * Callbacks installed by Swift so the engine can interact with the adapter.
 */
typedef struct BridgeCallbacks {
  EmitPacketsFn emit_packets;
  DialFn request_tcp_dial;
  DialFn request_udp_dial;
  SendFn tcp_send;
  SendFn udp_send;
  CloseFn tcp_close;
  CloseFn udp_close;
  RecordDnsFn record_dns;
  void *context;
} BridgeCallbacks;

typedef struct BridgeLogSink {
  void (*log)(const char *level, const char *message, uint32_t breadcrumbs, void *context);
  void *context;
  uint32_t enabled_breadcrumbs;
} BridgeLogSink;

typedef struct FlowCounters {
  uint64_t tcp_admission_fail;
  uint64_t udp_admission_fail;
  uint64_t tcp_backpressure_drops;
  uint64_t udp_backpressure_drops;
} FlowCounters;

typedef struct FlowStats {
  uint64_t poll_iterations;
  uint64_t frames_emitted;
  uint64_t bytes_emitted;
  uint64_t tcp_flush_events;
  uint64_t udp_flush_events;
} FlowStats;

typedef struct BridgeResolveResult {
  char **addresses;
  size_t count;
  void *storage;
  uint32_t ttl_seconds;
} BridgeResolveResult;

struct BridgeEngine *BridgeNewEngine(const struct BridgeConfig *config);

void BridgeFreeEngine(struct BridgeEngine *engine);

int32_t BridgeEngineStart(struct BridgeEngine *engine, const struct BridgeCallbacks *callbacks);

void BridgeEngineStop(struct BridgeEngine *engine);

bool BridgeSetLogSink(const struct BridgeLogSink *sink, const char *level, void **_error);

void BridgeSetBreadcrumbMask(uint32_t mask);

bool BridgeEngineHandlePacket(struct BridgeEngine *engine,
                              const uint8_t *packet,
                              size_t length,
                              uint32_t protocol);

bool BridgeEngineOnTcpReceive(struct BridgeEngine *engine,
                              uint64_t handle,
                              const uint8_t *payload,
                              size_t length);

bool BridgeEngineOnUdpReceive(struct BridgeEngine *engine,
                              uint64_t handle,
                              const uint8_t *payload,
                              size_t length);

void BridgeEngineOnTcpClose(struct BridgeEngine *engine, uint64_t handle);

void BridgeEngineOnUdpClose(struct BridgeEngine *engine, uint64_t handle);

void BridgeEngineOnDialResult(struct BridgeEngine *engine,
                              uint64_t handle,
                              bool success,
                              const char *message);

bool BridgeEngineGetCounters(struct BridgeEngine *engine, struct FlowCounters *out);

bool BridgeEngineGetStats(struct BridgeEngine *engine, struct FlowStats *out);

int32_t BridgeEngineResolveHost(struct BridgeEngine *engine,
                                const char *host,
                                struct BridgeResolveResult *result);

void BridgeResolveResultFree(struct BridgeResolveResult *result);

bool BridgeEnsureLinked(void);

#endif /* ENGINE_BRIDGE_H */
