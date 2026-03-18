#include "PacketIntelligenceCore.h"

#include <string.h>

#define RBPI_IPV4_MIN_HEADER_BYTES 20u
#define RBPI_IPV6_HEADER_BYTES 40u
#define RBPI_TCP_MIN_HEADER_BYTES 20u
#define RBPI_UDP_HEADER_BYTES 8u
#define RBPI_MAX_IPV6_EXTENSION_HEADERS 8u
#define RBPI_FNV_OFFSET_BASIS 14695981039346656037ull
#define RBPI_FNV_PRIME 1099511628211ull

static uint16_t rbpi_load_u16(const uint8_t *bytes)
{
    return (uint16_t)(((uint16_t)bytes[0] << 8) | (uint16_t)bytes[1]);
}

static uint32_t rbpi_load_u32(const uint8_t *bytes)
{
    return ((uint32_t)bytes[0] << 24) |
           ((uint32_t)bytes[1] << 16) |
           ((uint32_t)bytes[2] << 8) |
           (uint32_t)bytes[3];
}

static uint64_t rbpi_load_u64(const uint8_t *bytes)
{
    return ((uint64_t)bytes[0] << 56) |
           ((uint64_t)bytes[1] << 48) |
           ((uint64_t)bytes[2] << 40) |
           ((uint64_t)bytes[3] << 32) |
           ((uint64_t)bytes[4] << 24) |
           ((uint64_t)bytes[5] << 16) |
           ((uint64_t)bytes[6] << 8) |
           (uint64_t)bytes[7];
}

static uint64_t rbpi_fnv1a_update(uint64_t hash, const uint8_t *bytes, size_t length)
{
    size_t index;

    for (index = 0; index < length; index += 1) {
        hash ^= (uint64_t)bytes[index];
        hash *= RBPI_FNV_PRIME;
    }

    return hash;
}

static void rbpi_pack_address(const uint8_t *address, uint8_t length, uint64_t *out_high, uint64_t *out_low)
{
    uint8_t padded[16];

    memset(padded, 0, sizeof(padded));
    if (length > 0 && length <= sizeof(padded)) {
        memcpy(padded + (sizeof(padded) - length), address, length);
    }

    *out_high = rbpi_load_u64(padded);
    *out_low = rbpi_load_u64(padded + 8);
}

static uint64_t rbpi_hash_flow(
    uint8_t ip_version,
    uint8_t transport_protocol,
    const uint8_t *source_address,
    uint8_t source_address_length,
    const uint8_t *destination_address,
    uint8_t destination_address_length,
    uint16_t source_port,
    uint16_t destination_port)
{
    /* Keep flow identity numeric and allocation-free so Swift can cache by flow without rebuilding strings. */
    uint64_t hash = RBPI_FNV_OFFSET_BASIS;
    uint8_t ports[4];

    hash = rbpi_fnv1a_update(hash, &ip_version, 1);
    hash = rbpi_fnv1a_update(hash, &transport_protocol, 1);
    hash = rbpi_fnv1a_update(hash, &source_address_length, 1);
    hash = rbpi_fnv1a_update(hash, source_address, source_address_length);
    hash = rbpi_fnv1a_update(hash, &destination_address_length, 1);
    hash = rbpi_fnv1a_update(hash, destination_address, destination_address_length);

    ports[0] = (uint8_t)(source_port >> 8);
    ports[1] = (uint8_t)(source_port & 0xffu);
    ports[2] = (uint8_t)(destination_port >> 8);
    ports[3] = (uint8_t)(destination_port & 0xffu);

    return rbpi_fnv1a_update(hash, ports, sizeof(ports));
}

static bool rbpi_is_ipv6_extension_header(uint8_t header)
{
    switch (header) {
    case 0u:
    case 43u:
    case 44u:
    case 50u:
    case 51u:
    case 60u:
        return true;
    default:
        return false;
    }
}

/*
 * Reads only the QUIC long-header fields that are cheap and detector-friendly.
 * Payload decryption is intentionally deferred to the Swift layer.
 */
static void rbpi_fill_quic_metadata(const uint8_t *payload, size_t payload_length, rbpi_fast_packet_t *summary)
{
    uint8_t first_byte;
    uint8_t packet_type;
    uint8_t dcid_length;
    uint8_t scid_length;
    size_t index;

    summary->flags |= RBPI_FLAG_MAYBE_QUIC;

    if (payload_length == 0) {
        return;
    }

    first_byte = payload[0];
    if ((first_byte & 0x80u) == 0u) {
        return;
    }

    if (payload_length < 6) {
        return;
    }

    packet_type = (uint8_t)((first_byte & 0x30u) >> 4);
    summary->flags |= RBPI_FLAG_MAYBE_QUIC_LONG;
    summary->quic_packet_type = packet_type;
    summary->quic_version = rbpi_load_u32(payload + 1);

    index = 5;
    dcid_length = payload[index];
    index += 1;
    if (dcid_length > sizeof(summary->quic_dcid) || payload_length < index + dcid_length + 1) {
        return;
    }
    summary->quic_dcid_length = dcid_length;
    if (dcid_length > 0) {
        memcpy(summary->quic_dcid, payload + index, dcid_length);
    }
    index += dcid_length;

    scid_length = payload[index];
    index += 1;
    if (scid_length > sizeof(summary->quic_scid) || payload_length < index + scid_length) {
        summary->quic_dcid_length = 0;
        memset(summary->quic_dcid, 0, sizeof(summary->quic_dcid));
        return;
    }
    summary->quic_scid_length = scid_length;
    if (scid_length > 0) {
        memcpy(summary->quic_scid, payload + index, scid_length);
    }

    if ((summary->quic_version == 0x00000001u && packet_type == 0u) ||
        (summary->quic_version == 0x6b3343cfu && packet_type == 1u)) {
        summary->flags |= RBPI_FLAG_MAYBE_QUIC_INITIAL;
    }
}

static void rbpi_fill_tcp_metadata(const uint8_t *segment, size_t segment_length, rbpi_fast_packet_t *summary)
{
    uint8_t data_offset;
    uint16_t payload_offset;

    if (segment_length < RBPI_TCP_MIN_HEADER_BYTES) {
        return;
    }

    summary->source_port = rbpi_load_u16(segment);
    summary->destination_port = rbpi_load_u16(segment + 2);
    summary->flags |= RBPI_FLAG_HAS_PORTS;
    summary->tcp_flags = segment[13];
    if ((summary->tcp_flags & 0x02u) != 0u) {
        summary->flags |= RBPI_FLAG_TCP_SYN;
    }

    data_offset = (uint8_t)((segment[12] >> 4) * 4u);
    if (data_offset < RBPI_TCP_MIN_HEADER_BYTES || segment_length < data_offset) {
        return;
    }

    payload_offset = data_offset;
    summary->transport_payload_offset = payload_offset;

    if ((summary->source_port == 443u || summary->destination_port == 443u) &&
        segment_length > payload_offset && segment[payload_offset] == 22u) {
        summary->flags |= RBPI_FLAG_MAYBE_TLS_CLIENT_HELLO;
    }
}

static void rbpi_fill_udp_metadata(const uint8_t *segment, size_t segment_length, rbpi_fast_packet_t *summary)
{
    const uint8_t *payload;
    size_t payload_length;

    if (segment_length < RBPI_UDP_HEADER_BYTES) {
        return;
    }

    summary->source_port = rbpi_load_u16(segment);
    summary->destination_port = rbpi_load_u16(segment + 2);
    summary->flags |= RBPI_FLAG_HAS_PORTS;
    summary->transport_payload_offset = RBPI_UDP_HEADER_BYTES;

    if (summary->source_port == 53u || summary->destination_port == 53u) {
        summary->flags |= RBPI_FLAG_MAYBE_DNS;
    }

    /* UDP:443 is the only always-on path where we currently need cheap QUIC hints. */
    if (summary->source_port != 443u && summary->destination_port != 443u) {
        return;
    }

    payload = segment + RBPI_UDP_HEADER_BYTES;
    payload_length = segment_length - RBPI_UDP_HEADER_BYTES;
    rbpi_fill_quic_metadata(payload, payload_length, summary);
}

static bool rbpi_parse_ipv4(const uint8_t *bytes, size_t length, rbpi_fast_packet_t *summary)
{
    uint8_t version_and_ihl;
    size_t header_length;
    uint16_t fragment_field;
    const uint8_t *transport;
    size_t transport_length;

    if (length < RBPI_IPV4_MIN_HEADER_BYTES) {
        return false;
    }

    version_and_ihl = bytes[0];
    if ((version_and_ihl >> 4) != 4u) {
        return false;
    }

    header_length = (size_t)((version_and_ihl & 0x0fu) * 4u);
    if (header_length < RBPI_IPV4_MIN_HEADER_BYTES || length < header_length) {
        return false;
    }

    summary->ip_version = 4u;
    summary->transport_protocol = bytes[9];
    summary->source_address_length = 4u;
    summary->destination_address_length = 4u;
    rbpi_pack_address(bytes + 12, 4u, &summary->source_address_high, &summary->source_address_low);
    rbpi_pack_address(bytes + 16, 4u, &summary->destination_address_high, &summary->destination_address_low);

    /*
     * Later IPv4 fragments do not carry transport headers. Mark them and stop once
     * the parser can no longer trust ports or higher-level protocol hints.
     */
    fragment_field = rbpi_load_u16(bytes + 6);
    if ((fragment_field & 0x3fffu) != 0u || (fragment_field & 0x2000u) != 0u) {
        summary->flags |= RBPI_FLAG_IS_FRAGMENT;
        if ((fragment_field & 0x1fffu) != 0u) {
            return true;
        }
    }

    transport = bytes + header_length;
    transport_length = length - header_length;

    if (summary->transport_protocol == 6u) {
        rbpi_fill_tcp_metadata(transport, transport_length, summary);
    } else if (summary->transport_protocol == 17u) {
        rbpi_fill_udp_metadata(transport, transport_length, summary);
    }

    if (summary->transport_payload_offset > 0u) {
        summary->transport_payload_offset = (uint16_t)(summary->transport_payload_offset + header_length);
    }

    return true;
}

static bool rbpi_parse_ipv6(const uint8_t *bytes, size_t length, rbpi_fast_packet_t *summary)
{
    uint8_t next_header;
    size_t offset;
    uint8_t extensions_seen;
    const uint8_t *transport;
    size_t transport_length;

    if (length < RBPI_IPV6_HEADER_BYTES || (bytes[0] >> 4) != 6u) {
        return false;
    }

    summary->ip_version = 6u;
    summary->source_address_length = 16u;
    summary->destination_address_length = 16u;
    rbpi_pack_address(bytes + 8, 16u, &summary->source_address_high, &summary->source_address_low);
    rbpi_pack_address(bytes + 24, 16u, &summary->destination_address_high, &summary->destination_address_low);

    next_header = bytes[6];
    offset = RBPI_IPV6_HEADER_BYTES;
    extensions_seen = 0u;

    /* Walk a bounded number of extension headers so hostile packets cannot turn this into an unbounded scan. */
    while (rbpi_is_ipv6_extension_header(next_header) && extensions_seen < RBPI_MAX_IPV6_EXTENSION_HEADERS) {
        uint8_t current_header;
        uint8_t length_field;
        size_t header_length;

        if (length < offset + 2) {
            return false;
        }

        current_header = next_header;
        next_header = bytes[offset];
        length_field = bytes[offset + 1];

        switch (current_header) {
        case 44u:
            header_length = 8u;
            summary->flags |= RBPI_FLAG_IS_FRAGMENT;
            break;
        case 51u:
            header_length = (size_t)(length_field + 2u) * 4u;
            break;
        case 50u:
            summary->transport_protocol = current_header;
            return true;
        default:
            header_length = (size_t)(length_field + 1u) * 8u;
            break;
        }

        if (length < offset + header_length) {
            return false;
        }

        offset += header_length;
        extensions_seen += 1u;
    }

    summary->transport_protocol = next_header;
    if (length < offset) {
        return false;
    }

    transport = bytes + offset;
    transport_length = length - offset;

    if (summary->transport_protocol == 6u) {
        rbpi_fill_tcp_metadata(transport, transport_length, summary);
    } else if (summary->transport_protocol == 17u) {
        rbpi_fill_udp_metadata(transport, transport_length, summary);
    }

    if (summary->transport_payload_offset > 0u) {
        summary->transport_payload_offset = (uint16_t)(summary->transport_payload_offset + offset);
    }

    return true;
}

bool rbpi_parse_packet(const uint8_t *bytes, size_t length, int32_t family_hint, rbpi_fast_packet_t *out_summary)
{
    uint8_t version;
    uint8_t source_address[16];
    uint8_t destination_address[16];

    if (bytes == NULL || out_summary == NULL || length == 0) {
        return false;
    }

    memset(out_summary, 0, sizeof(*out_summary));
    out_summary->quic_packet_type = RBPI_QUIC_PACKET_TYPE_UNKNOWN;
    out_summary->packet_length = (uint32_t)length;

    version = (uint8_t)(bytes[0] >> 4);
    if (version == 4u) {
        if (!rbpi_parse_ipv4(bytes, length, out_summary)) {
            return false;
        }
    } else if (version == 6u) {
        if (!rbpi_parse_ipv6(bytes, length, out_summary)) {
            return false;
        }
    } else if (family_hint == 2) {
        if (!rbpi_parse_ipv4(bytes, length, out_summary)) {
            return false;
        }
    } else if (family_hint == 30) {
        if (!rbpi_parse_ipv6(bytes, length, out_summary)) {
            return false;
        }
    } else {
        return false;
    }

    memset(source_address, 0, sizeof(source_address));
    memset(destination_address, 0, sizeof(destination_address));

    if (out_summary->source_address_length > 0u) {
        uint8_t source_padded[16];
        uint8_t destination_padded[16];
        size_t source_offset = (size_t)(16u - out_summary->source_address_length);
        size_t destination_offset = (size_t)(16u - out_summary->destination_address_length);

        memset(source_padded, 0, sizeof(source_padded));
        memset(destination_padded, 0, sizeof(destination_padded));

        source_padded[0] = 0u;
        destination_padded[0] = 0u;

        /*
         * Addresses are stored in packed integer form for the Swift fast path.
         * Rehydrate them only here so the flow hash is computed from canonical bytes.
         */
        if (out_summary->source_address_length == 4u) {
            source_padded[source_offset + 0] = (uint8_t)(out_summary->source_address_low >> 24);
            source_padded[source_offset + 1] = (uint8_t)(out_summary->source_address_low >> 16);
            source_padded[source_offset + 2] = (uint8_t)(out_summary->source_address_low >> 8);
            source_padded[source_offset + 3] = (uint8_t)(out_summary->source_address_low);
            destination_padded[destination_offset + 0] = (uint8_t)(out_summary->destination_address_low >> 24);
            destination_padded[destination_offset + 1] = (uint8_t)(out_summary->destination_address_low >> 16);
            destination_padded[destination_offset + 2] = (uint8_t)(out_summary->destination_address_low >> 8);
            destination_padded[destination_offset + 3] = (uint8_t)(out_summary->destination_address_low);
        } else {
            source_padded[0] = (uint8_t)(out_summary->source_address_high >> 56);
            source_padded[1] = (uint8_t)(out_summary->source_address_high >> 48);
            source_padded[2] = (uint8_t)(out_summary->source_address_high >> 40);
            source_padded[3] = (uint8_t)(out_summary->source_address_high >> 32);
            source_padded[4] = (uint8_t)(out_summary->source_address_high >> 24);
            source_padded[5] = (uint8_t)(out_summary->source_address_high >> 16);
            source_padded[6] = (uint8_t)(out_summary->source_address_high >> 8);
            source_padded[7] = (uint8_t)(out_summary->source_address_high);
            source_padded[8] = (uint8_t)(out_summary->source_address_low >> 56);
            source_padded[9] = (uint8_t)(out_summary->source_address_low >> 48);
            source_padded[10] = (uint8_t)(out_summary->source_address_low >> 40);
            source_padded[11] = (uint8_t)(out_summary->source_address_low >> 32);
            source_padded[12] = (uint8_t)(out_summary->source_address_low >> 24);
            source_padded[13] = (uint8_t)(out_summary->source_address_low >> 16);
            source_padded[14] = (uint8_t)(out_summary->source_address_low >> 8);
            source_padded[15] = (uint8_t)(out_summary->source_address_low);

            destination_padded[0] = (uint8_t)(out_summary->destination_address_high >> 56);
            destination_padded[1] = (uint8_t)(out_summary->destination_address_high >> 48);
            destination_padded[2] = (uint8_t)(out_summary->destination_address_high >> 40);
            destination_padded[3] = (uint8_t)(out_summary->destination_address_high >> 32);
            destination_padded[4] = (uint8_t)(out_summary->destination_address_high >> 24);
            destination_padded[5] = (uint8_t)(out_summary->destination_address_high >> 16);
            destination_padded[6] = (uint8_t)(out_summary->destination_address_high >> 8);
            destination_padded[7] = (uint8_t)(out_summary->destination_address_high);
            destination_padded[8] = (uint8_t)(out_summary->destination_address_low >> 56);
            destination_padded[9] = (uint8_t)(out_summary->destination_address_low >> 48);
            destination_padded[10] = (uint8_t)(out_summary->destination_address_low >> 40);
            destination_padded[11] = (uint8_t)(out_summary->destination_address_low >> 32);
            destination_padded[12] = (uint8_t)(out_summary->destination_address_low >> 24);
            destination_padded[13] = (uint8_t)(out_summary->destination_address_low >> 16);
            destination_padded[14] = (uint8_t)(out_summary->destination_address_low >> 8);
            destination_padded[15] = (uint8_t)(out_summary->destination_address_low);
        }

        memcpy(source_address, source_padded + (16u - out_summary->source_address_length), out_summary->source_address_length);
        memcpy(destination_address, destination_padded + (16u - out_summary->destination_address_length), out_summary->destination_address_length);
    }

    out_summary->flow_hash = rbpi_hash_flow(
        out_summary->ip_version,
        out_summary->transport_protocol,
        source_address,
        out_summary->source_address_length,
        destination_address,
        out_summary->destination_address_length,
        out_summary->source_port,
        out_summary->destination_port
    );
    out_summary->reverse_flow_hash = rbpi_hash_flow(
        out_summary->ip_version,
        out_summary->transport_protocol,
        destination_address,
        out_summary->destination_address_length,
        source_address,
        out_summary->source_address_length,
        out_summary->destination_port,
        out_summary->source_port
    );

    return true;
}
