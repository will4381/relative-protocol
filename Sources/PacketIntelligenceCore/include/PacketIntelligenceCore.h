#ifndef PACKET_INTELLIGENCE_CORE_H
#define PACKET_INTELLIGENCE_CORE_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

enum {
    RBPI_FLAG_HAS_PORTS = 1u << 0,
    RBPI_FLAG_TCP_SYN = 1u << 1,
    RBPI_FLAG_IS_FRAGMENT = 1u << 2,
    RBPI_FLAG_MAYBE_DNS = 1u << 3,
    RBPI_FLAG_MAYBE_TLS_CLIENT_HELLO = 1u << 4,
    RBPI_FLAG_MAYBE_QUIC = 1u << 5,
    RBPI_FLAG_MAYBE_QUIC_LONG = 1u << 6,
    RBPI_FLAG_MAYBE_QUIC_INITIAL = 1u << 7,
};

enum {
    RBPI_QUIC_PACKET_TYPE_UNKNOWN = 255u,
};

/*
 * Fixed-size packet summary emitted by the C fast path.
 *
 * Design notes:
 * - The struct is intentionally string-free and heap-free so the tunnel can parse
 *   a packet with predictable cost on the always-on path.
 * - Addresses are stored as packed 128-bit values (`*_high` + `*_low`) so Swift
 *   can cache string rendering once per flow instead of once per packet.
 * - QUIC metadata is limited to the long-header fields that are cheap to read
 *   without decrypting payloads.
 */
typedef struct rbpi_fast_packet_s {
    uint8_t ip_version;
    uint8_t transport_protocol;
    uint8_t flags;
    uint8_t source_address_length;
    uint8_t destination_address_length;
    uint8_t tcp_flags;
    uint8_t quic_packet_type;
    uint8_t reserved0;
    uint16_t source_port;
    uint16_t destination_port;
    uint16_t transport_payload_offset;
    uint16_t reserved1;
    uint32_t packet_length;
    uint32_t quic_version;
    uint64_t flow_hash;
    uint64_t reverse_flow_hash;
    uint64_t source_address_high;
    uint64_t source_address_low;
    uint64_t destination_address_high;
    uint64_t destination_address_low;
    uint8_t quic_dcid_length;
    uint8_t quic_scid_length;
    uint8_t reserved2[2];
    uint8_t quic_dcid[20];
    uint8_t quic_scid[20];
} rbpi_fast_packet_t;

/*
 * Parses a raw IPv4/IPv6 packet into a fixed summary.
 *
 * Returns `false` for malformed or unsupported frames. On success the caller owns
 * a fully initialized `rbpi_fast_packet_t` and can forward it into higher-level
 * Swift caches without doing any additional packet-header parsing.
 */
bool rbpi_parse_packet(const uint8_t *bytes, size_t length, int32_t family_hint, rbpi_fast_packet_t *out_summary);

#ifdef __cplusplus
}
#endif

#endif
