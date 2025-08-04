#include "packet/tunnel_provider.h"
#include "core/logging.h"
#include <stdlib.h>
#include <string.h>
#include <pthread.h>

#ifdef TARGET_OS_IOS
#import <NetworkExtension/NetworkExtension.h>
#import <Network/Network.h>
#endif

#define PACKET_QUEUE_SIZE 1000
#define READ_BUFFER_SIZE 65536

struct tunnel_provider {
    tunnel_packet_handler_t packet_handler;
    void *user_data;
    
    // Packet processing queue
    packet_info_t *packet_queue;
    size_t queue_size;
    size_t queue_head;
    size_t queue_tail;
    pthread_mutex_t queue_mutex;
    pthread_cond_t queue_cond;
    
    // Statistics
    vpn_metrics_t stats;
    pthread_mutex_t stats_mutex;
    
    // Read buffer for packet flow
    uint8_t *read_buffer;
    size_t buffer_size;
    
    bool running;
    
#ifdef TARGET_OS_IOS
    NEPacketTunnelFlow *packet_flow;
    dispatch_queue_t packet_queue_dispatch;
#endif
};

tunnel_provider_t *tunnel_provider_create(void) {
    tunnel_provider_t *provider = (tunnel_provider_t *)calloc(1, sizeof(tunnel_provider_t));
    if (!provider) {
        LOG_ERROR("Failed to allocate tunnel provider");
        return NULL;
    }
    
    // Initialize mutexes
    if (pthread_mutex_init(&provider->queue_mutex, NULL) != 0) {
        LOG_ERROR("Failed to initialize queue mutex");
        free(provider);
        return NULL;
    }
    
    if (pthread_cond_init(&provider->queue_cond, NULL) != 0) {
        LOG_ERROR("Failed to initialize queue condition");
        pthread_mutex_destroy(&provider->queue_mutex);
        free(provider);
        return NULL;
    }
    
    if (pthread_mutex_init(&provider->stats_mutex, NULL) != 0) {
        LOG_ERROR("Failed to initialize stats mutex");
        pthread_cond_destroy(&provider->queue_cond);
        pthread_mutex_destroy(&provider->queue_mutex);
        free(provider);
        return NULL;
    }
    
    // Allocate packet queue
    provider->queue_size = PACKET_QUEUE_SIZE;
    provider->packet_queue = (packet_info_t *)calloc(provider->queue_size, sizeof(packet_info_t));
    if (!provider->packet_queue) {
        LOG_ERROR("Failed to allocate packet queue");
        pthread_mutex_destroy(&provider->stats_mutex);
        pthread_cond_destroy(&provider->queue_cond);
        pthread_mutex_destroy(&provider->queue_mutex);
        free(provider);
        return NULL;
    }
    
    // Allocate read buffer
    provider->buffer_size = READ_BUFFER_SIZE;
    provider->read_buffer = (uint8_t *)malloc(provider->buffer_size);
    if (!provider->read_buffer) {
        LOG_ERROR("Failed to allocate read buffer");
        free(provider->packet_queue);
        pthread_mutex_destroy(&provider->stats_mutex);
        pthread_cond_destroy(&provider->queue_cond);
        pthread_mutex_destroy(&provider->queue_mutex);
        free(provider);
        return NULL;
    }
    
#ifdef TARGET_OS_IOS
    // Create dispatch queue for packet processing
    provider->packet_queue_dispatch = dispatch_queue_create("com.relative.vpn.packet", 
                                                          DISPATCH_QUEUE_SERIAL);
    if (!provider->packet_queue_dispatch) {
        LOG_ERROR("Failed to create dispatch queue");
        free(provider->read_buffer);
        free(provider->packet_queue);
        pthread_mutex_destroy(&provider->stats_mutex);
        pthread_cond_destroy(&provider->queue_cond);
        pthread_mutex_destroy(&provider->queue_mutex);
        free(provider);
        return NULL;
    }
#endif
    
    provider->running = true;
    
    LOG_INFO("Tunnel provider created");
    return provider;
}

void tunnel_provider_destroy(tunnel_provider_t *provider) {
    if (!provider) return;
    
    provider->running = false;
    
    // Signal any waiting threads
    pthread_cond_broadcast(&provider->queue_cond);
    
#ifdef TARGET_OS_IOS
    if (provider->packet_queue_dispatch) {
        dispatch_release(provider->packet_queue_dispatch);
        provider->packet_queue_dispatch = NULL;
    }
    
    provider->packet_flow = nil;
#endif
    
    // Free resources
    if (provider->read_buffer) {
        free(provider->read_buffer);
        provider->read_buffer = NULL;
    }
    
    if (provider->packet_queue) {
        free(provider->packet_queue);
        provider->packet_queue = NULL;
    }
    
    pthread_mutex_destroy(&provider->stats_mutex);
    pthread_cond_destroy(&provider->queue_cond);
    pthread_mutex_destroy(&provider->queue_mutex);
    
    free(provider);
    LOG_INFO("Tunnel provider destroyed");
}

bool tunnel_provider_set_packet_handler(tunnel_provider_t *provider,
                                       tunnel_packet_handler_t handler,
                                       void *user_data) {
    if (!provider) return false;
    
    provider->packet_handler = handler;
    provider->user_data = user_data;
    return true;
}

bool tunnel_provider_send_packet(tunnel_provider_t *provider,
                                const uint8_t *data,
                                size_t length) {
    if (!provider || !data || length == 0) return false;
    
#ifdef TARGET_OS_IOS
    if (!provider->packet_flow) {
        LOG_ERROR("Packet flow not configured");
        return false;
    }
    
    @autoreleasepool {
        NSData *packetData = [NSData dataWithBytes:data length:length];
        NSArray<NSData *> *packets = @[packetData];
        NSArray<NSNumber *> *protocols = @[@(AF_INET)]; // IPv4
        
        // Check IP version from packet
        if (length > 0) {
            uint8_t version = (data[0] >> 4) & 0x0F;
            if (version == 6) {
                protocols = @[@(AF_INET6)]; // IPv6
            }
        }
        
        BOOL success = [provider->packet_flow writePackets:packets 
                                             withProtocols:protocols];
        
        if (success) {
            pthread_mutex_lock(&provider->stats_mutex);
            provider->stats.bytes_sent += length;
            provider->stats.total_packets_processed++;
            pthread_mutex_unlock(&provider->stats_mutex);
            
            LOG_TRACE("Sent packet of %zu bytes to tunnel", length);
        } else {
            LOG_ERROR("Failed to write packet to tunnel flow");
            
            pthread_mutex_lock(&provider->stats_mutex);
            provider->stats.packet_errors++;
            pthread_mutex_unlock(&provider->stats_mutex);
        }
        
        return success;
    }
#else
    LOG_ERROR("Tunnel provider requires iOS platform");
    return false;
#endif
}

bool tunnel_provider_process_packets(tunnel_provider_t *provider) {
    if (!provider) return false;
    
    pthread_mutex_lock(&provider->queue_mutex);
    
    while (provider->queue_head != provider->queue_tail && provider->running) {
        packet_info_t packet = provider->packet_queue[provider->queue_head];
        provider->queue_head = (provider->queue_head + 1) % provider->queue_size;
        
        pthread_mutex_unlock(&provider->queue_mutex);
        
        // Call packet handler
        if (provider->packet_handler) {
            provider->packet_handler(&packet, provider->user_data);
        }
        
        pthread_mutex_lock(&provider->queue_mutex);
    }
    
    pthread_mutex_unlock(&provider->queue_mutex);
    return true;
}

void tunnel_provider_get_stats(tunnel_provider_t *provider, vpn_metrics_t *metrics) {
    if (!provider || !metrics) return;
    
    pthread_mutex_lock(&provider->stats_mutex);
    memcpy(metrics, &provider->stats, sizeof(vpn_metrics_t));
    pthread_mutex_unlock(&provider->stats_mutex);
}

#ifdef TARGET_OS_IOS
bool tunnel_provider_configure_packet_flow(tunnel_provider_t *provider,
                                         NEPacketTunnelFlow *packetFlow) {
    if (!provider || !packetFlow) return false;
    
    provider->packet_flow = packetFlow;
    
    // Start reading packets from the tunnel
    __weak typeof(provider) weakProvider = provider;
    
    void (^readHandler)(void) = ^{
        __strong typeof(weakProvider) strongProvider = weakProvider;
        if (!strongProvider || !strongProvider->running) return;
        
        [strongProvider->packet_flow readPacketsWithCompletionHandler:^(NSArray<NSData *> *packets, 
                                                                       NSArray<NSNumber *> *protocols) {
            if (!strongProvider->running) return;
            
            // Process each packet
            for (NSUInteger i = 0; i < packets.count; i++) {
                NSData *packetData = packets[i];
                NSNumber *protocolFamily = protocols[i];
                
                if (packetData.length == 0 || packetData.length > MAX_PACKET_SIZE) {
                    pthread_mutex_lock(&strongProvider->stats_mutex);
                    strongProvider->stats.packet_errors++;
                    pthread_mutex_unlock(&strongProvider->stats_mutex);
                    continue;
                }
                
                // Create packet info
                packet_info_t packet = {0};
                packet.length = packetData.length;
                packet.data = (const uint8_t *)packetData.bytes;
                packet.timestamp_ns = clock_gettime_nsec_np(CLOCK_MONOTONIC);
                
                // Determine IP version from protocol family
                if (protocolFamily.intValue == AF_INET) {
                    packet.flow.ip_version = 4;
                } else if (protocolFamily.intValue == AF_INET6) {
                    packet.flow.ip_version = 6;
                } else {
                    pthread_mutex_lock(&strongProvider->stats_mutex);
                    strongProvider->stats.packet_errors++;
                    pthread_mutex_unlock(&strongProvider->stats_mutex);
                    continue;
                }
                
                // Parse basic flow information from packet
                if (packet.flow.ip_version == 4 && packet.length >= 20) {
                    // IPv4 header parsing
                    const uint8_t *ip_header = packet.data;
                    packet.flow.protocol = ip_header[9];
                    memcpy(&packet.flow.src_ip.v4.addr, &ip_header[12], 4);
                    memcpy(&packet.flow.dst_ip.v4.addr, &ip_header[16], 4);
                    
                    // Parse port information if TCP/UDP
                    uint8_t ihl = (ip_header[0] & 0x0F) * 4;
                    if ((packet.flow.protocol == PROTO_TCP || packet.flow.protocol == PROTO_UDP) &&
                        packet.length >= ihl + 4) {
                        const uint8_t *transport = packet.data + ihl;
                        packet.flow.src_port = (transport[0] << 8) | transport[1];
                        packet.flow.dst_port = (transport[2] << 8) | transport[3];
                    }
                } else if (packet.flow.ip_version == 6 && packet.length >= 40) {
                    // IPv6 header parsing
                    const uint8_t *ip6_header = packet.data;
                    packet.flow.protocol = ip6_header[6];
                    memcpy(&packet.flow.src_ip.v6.addr, &ip6_header[8], 16);
                    memcpy(&packet.flow.dst_ip.v6.addr, &ip6_header[24], 16);
                    
                    // Parse port information if TCP/UDP
                    if ((packet.flow.protocol == PROTO_TCP || packet.flow.protocol == PROTO_UDP) &&
                        packet.length >= 44) {
                        const uint8_t *transport = packet.data + 40;
                        packet.flow.src_port = (transport[0] << 8) | transport[1];
                        packet.flow.dst_port = (transport[2] << 8) | transport[3];
                    }
                }
                
                // Add to processing queue
                pthread_mutex_lock(&strongProvider->queue_mutex);
                
                size_t next_tail = (strongProvider->queue_tail + 1) % strongProvider->queue_size;
                if (next_tail != strongProvider->queue_head) {
                    // Copy packet data to queue buffer
                    packet_info_t *queued_packet = &strongProvider->packet_queue[strongProvider->queue_tail];
                    *queued_packet = packet;
                    
                    // Allocate and copy data since NSData will be released
                    uint8_t *packet_copy = (uint8_t *)malloc(packet.length);
                    if (packet_copy) {
                        memcpy(packet_copy, packet.data, packet.length);
                        queued_packet->data = packet_copy;
                        
                        strongProvider->queue_tail = next_tail;
                        pthread_cond_signal(&strongProvider->queue_cond);
                        
                        pthread_mutex_lock(&strongProvider->stats_mutex);
                        strongProvider->stats.bytes_received += packet.length;
                        strongProvider->stats.total_packets_processed++;
                        pthread_mutex_unlock(&strongProvider->stats_mutex);
                    } else {
                        pthread_mutex_lock(&strongProvider->stats_mutex);
                        strongProvider->stats.packet_errors++;
                        pthread_mutex_unlock(&strongProvider->stats_mutex);
                    }
                } else {
                    // Queue full
                    pthread_mutex_lock(&strongProvider->stats_mutex);
                    strongProvider->stats.packet_errors++;
                    pthread_mutex_unlock(&strongProvider->stats_mutex);
                }
                
                pthread_mutex_unlock(&strongProvider->queue_mutex);
            }
            
            // Continue reading if still running
            if (strongProvider->running) {
                dispatch_async(strongProvider->packet_queue_dispatch, readHandler);
            }
        }];
    };
    
    // Start reading packets
    dispatch_async(provider->packet_queue_dispatch, readHandler);
    
    LOG_INFO("Configured packet flow for tunnel provider");
    return true;
}

bool tunnel_provider_create_tcp_connection(tunnel_provider_t *provider,
                                         NEPacketTunnelProvider *tunnelProvider,
                                         const char *hostname,
                                         uint16_t port,
                                         void (^completion)(NWTCPConnection *)) {
    if (!provider || !tunnelProvider || !hostname || !completion) return false;
    
    @autoreleasepool {
        NWHostEndpoint *endpoint = [NWHostEndpoint endpointWithHostname:@(hostname) 
                                                                   port:@(port).stringValue];
        
        NWTCPConnection *connection = [tunnelProvider createTCPConnectionToEndpoint:endpoint
                                                                        enableTLS:NO
                                                                    TLSParameters:nil
                                                                         delegate:nil];
        
        if (connection) {
            completion(connection);
            
            pthread_mutex_lock(&provider->stats_mutex);
            provider->stats.tcp_connections++;
            pthread_mutex_unlock(&provider->stats_mutex);
            
            LOG_DEBUG("Created TCP connection to %s:%d", hostname, port);
            return true;
        }
        
        LOG_ERROR("Failed to create TCP connection to %s:%d", hostname, port);
        return false;
    }
}

bool tunnel_provider_create_udp_session(tunnel_provider_t *provider,
                                      NEPacketTunnelProvider *tunnelProvider,
                                      const char *hostname,
                                      uint16_t port,
                                      void (^completion)(NWUDPSession *)) {
    if (!provider || !tunnelProvider || !hostname || !completion) return false;
    
    @autoreleasepool {
        NWHostEndpoint *endpoint = [NWHostEndpoint endpointWithHostname:@(hostname) 
                                                                   port:@(port).stringValue];
        
        NWUDPSession *session = [tunnelProvider createUDPSessionToEndpoint:endpoint
                                                              fromEndpoint:nil];
        
        if (session) {
            completion(session);
            
            pthread_mutex_lock(&provider->stats_mutex);
            provider->stats.udp_sessions++;
            pthread_mutex_unlock(&provider->stats_mutex);
            
            LOG_DEBUG("Created UDP session to %s:%d", hostname, port);
            return true;
        }
        
        LOG_ERROR("Failed to create UDP session to %s:%d", hostname, port);
        return false;
    }
}
#endif // TARGET_OS_IOS