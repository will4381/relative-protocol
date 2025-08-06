#ifndef RELATIVE_VPN_TUNNEL_PROVIDER_H
#define RELATIVE_VPN_TUNNEL_PROVIDER_H

#include "core/types.h"
#include "api/relative_vpn.h"
#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

// Forward declaration for iOS NetworkExtension integration
typedef struct tunnel_provider tunnel_provider_t;

// Callback for receiving packets from the tunnel interface
typedef void (*tunnel_packet_handler_t)(const packet_info_t * _Nonnull packet, void * _Nullable user_data);

// Create a new tunnel provider instance
tunnel_provider_t * _Nullable tunnel_provider_create(void);

// Destroy the tunnel provider
void tunnel_provider_destroy(tunnel_provider_t * _Nullable provider);

// Set packet handler callback
bool tunnel_provider_set_packet_handler(tunnel_provider_t * _Nonnull provider,
                                       tunnel_packet_handler_t _Nullable handler,
                                       void * _Nullable user_data);

// Send packet to the tunnel interface
bool tunnel_provider_send_packet(tunnel_provider_t * _Nonnull provider,
                                const uint8_t * _Nonnull data,
                                size_t length);

// Process packets from the tunnel - call this from NEPacketTunnelProvider
bool tunnel_provider_process_packets(tunnel_provider_t * _Nonnull provider);

// Get statistics
void tunnel_provider_get_stats(tunnel_provider_t * _Nonnull provider, vpn_metrics_t * _Nonnull metrics);

#ifdef TARGET_OS_IOS
#ifdef __OBJC__
#import <NetworkExtension/NetworkExtension.h>
#import <Network/Network.h>

// iOS-specific NetworkExtension integration
bool tunnel_provider_configure_packet_flow(tunnel_provider_t * _Nonnull provider,
                                         NEPacketTunnelFlow * _Nonnull packetFlow);

// Create TCP connection using NEPacketTunnelProvider
bool tunnel_provider_create_tcp_connection(tunnel_provider_t * _Nonnull provider,
                                         NEPacketTunnelProvider * _Nonnull tunnelProvider,
                                         const char * _Nonnull hostname,
                                         uint16_t port,
                                         void (^ _Nonnull completion)(nw_connection_t _Nullable));

// Create UDP session using NEPacketTunnelProvider
bool tunnel_provider_create_udp_session(tunnel_provider_t * _Nonnull provider,
                                      NEPacketTunnelProvider * _Nonnull tunnelProvider,
                                      const char * _Nonnull hostname,
                                      uint16_t port,
                                      void (^ _Nonnull completion)(nw_connection_t _Nullable));
#endif
#endif

#ifdef __cplusplus
}
#endif

#endif // RELATIVE_VPN_TUNNEL_PROVIDER_H