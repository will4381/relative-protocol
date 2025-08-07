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
    LOG_TRACE("Sending packet to tunnel: length=%zu", length);
    
    if (!provider || !data || length == 0) {
        LOG_ERROR("Invalid parameters for tunnel packet send: provider=%p, data=%p, length=%zu", 
                  provider, data, length);
        return false;
    }
    
    if (length > MAX_PACKET_SIZE) {
        LOG_ERROR("Packet too large for tunnel: %zu bytes (max %d)", length, MAX_PACKET_SIZE);
        return false;
    }
    
#ifdef TARGET_OS_IOS
    if (!provider->packet_flow) {
        LOG_ERROR("Packet flow not configured - cannot send packet");
        return false;
    }
    
    @autoreleasepool {
        // Parse and log packet details
        uint8_t ip_version = 0;
        const char* protocol_name = "Unknown";
        if (length >= 20) {
            ip_version = (data[0] >> 4) & 0x0F;
            if (ip_version == 4 && length >= 20) {
                uint8_t protocol = data[9];
                uint32_t src_ip, dst_ip;
                memcpy(&src_ip, &data[12], 4);
                memcpy(&dst_ip, &data[16], 4);
                
                uint16_t src_port = 0, dst_port = 0;
                if ((protocol == 6 || protocol == 17) && length >= 24) {
                    src_port = (data[20] << 8) | data[21];
                    dst_port = (data[22] << 8) | data[23];
                }
                
                struct in_addr src_addr = {.s_addr = src_ip};
                struct in_addr dst_addr = {.s_addr = dst_ip};
                
                if (protocol == 6) protocol_name = "TCP";
                else if (protocol == 17) protocol_name = "UDP";
                else if (protocol == 1) protocol_name = "ICMP";
                
                LOG_TRACE("Sending IPv4 packet: %s:%d -> %s:%d (%s, %zu bytes)",
                          inet_ntoa(src_addr), src_port,
                          inet_ntoa(dst_addr), dst_port,
                          protocol_name, length);
            } else if (ip_version == 6 && length >= 40) {
                uint8_t next_header = data[6];
                if (next_header == 6) protocol_name = "TCP";
                else if (next_header == 17) protocol_name = "UDP";
                else if (next_header == 58) protocol_name = "ICMPv6";
                
                LOG_TRACE("Sending IPv6 packet: %s (%zu bytes)", protocol_name, length);
            }
        }
        
        NSData *packetData = [NSData dataWithBytes:data length:length];
        NSArray<NSData *> *packets = @[packetData];
        NSArray<NSNumber *> *protocols = @[@(AF_INET)]; // IPv4
        
        // Check IP version from packet
        if (length > 0) {
            uint8_t version = (data[0] >> 4) & 0x0F;
            if (version == 6) {
                protocols = @[@(AF_INET6)]; // IPv6
                LOG_TRACE("Setting protocol family to IPv6");
            } else if (version == 4) {
                LOG_TRACE("Setting protocol family to IPv4");
            } else {
                LOG_WARN("Unknown IP version: %d", version);
            }
        }
        
        LOG_DEBUG("Writing packet to tunnel flow: %zu bytes, IP version %d", length, ip_version);
        BOOL success = [provider->packet_flow writePackets:packets 
                                             withProtocols:protocols];
        
        if (success) {
            pthread_mutex_lock(&provider->stats_mutex);
            provider->stats.bytes_sent += length;
            provider->stats.total_packets_processed++;
            pthread_mutex_unlock(&provider->stats_mutex);
            
            LOG_DEBUG("Successfully sent %s packet of %zu bytes to tunnel", protocol_name, length);
        } else {
            LOG_ERROR("Failed to write %s packet (%zu bytes) to tunnel flow", protocol_name, length);
            
            pthread_mutex_lock(&provider->stats_mutex);
            provider->stats.packet_errors++;
            pthread_mutex_unlock(&provider->stats_mutex);
        }
        
        return success;
    }
#else
    LOG_ERROR("Tunnel provider requires iOS platform - cannot send packet");
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
    // Note: provider is a C struct pointer, not an Objective-C object, so we can't use __weak
    tunnel_provider_t *providerPtr = provider;
    
    void (^readHandler)(void) = ^{
        tunnel_provider_t *strongProvider = providerPtr;
        if (!strongProvider || !strongProvider->running) return;
        
        [strongProvider->packet_flow readPacketsWithCompletionHandler:^(NSArray<NSData *> *packets, 
                                                                       NSArray<NSNumber *> *protocols) {
            if (!strongProvider->running) {
                LOG_TRACE("Tunnel provider not running, ignoring received packets");
                return;
            }
            
            LOG_TRACE("Received %lu packets from tunnel", (unsigned long)packets.count);
            
            // Process each packet
            for (NSUInteger i = 0; i < packets.count; i++) {
                NSData *packetData = packets[i];
                NSNumber *protocolFamily = protocols[i];
                
                LOG_TRACE("Processing packet %lu: length=%lu, protocol_family=%d", 
                         (unsigned long)i, (unsigned long)packetData.length, protocolFamily.intValue);
                
                if (packetData.length == 0 || packetData.length > MAX_PACKET_SIZE) {
                    LOG_ERROR("Invalid packet size: %lu bytes (max %d)", 
                             (unsigned long)packetData.length, MAX_PACKET_SIZE);
                    
                    pthread_mutex_lock(&strongProvider->stats_mutex);
                    strongProvider->stats.packet_errors++;
                    pthread_mutex_unlock(&strongProvider->stats_mutex);
                    continue;
                }
                
                // Create packet info
                packet_info_t packet = {0};
                packet.length = packetData.length;
                // We'll copy the data later to avoid const issues
                packet.data = (uint8_t *)packetData.bytes;
                packet.timestamp_ns = clock_gettime_nsec_np(CLOCK_MONOTONIC);
                
                LOG_TRACE("Created packet info: length=%zu, timestamp=%llu", 
                         packet.length, packet.timestamp_ns);
                
                // Determine IP version from protocol family
                if (protocolFamily.intValue == AF_INET) {
                    packet.flow.ip_version = 4;
                    LOG_TRACE("Packet is IPv4");
                } else if (protocolFamily.intValue == AF_INET6) {
                    packet.flow.ip_version = 6;
                    LOG_TRACE("Packet is IPv6");
                } else {
                    LOG_ERROR("Unknown protocol family: %d", protocolFamily.intValue);
                    
                    pthread_mutex_lock(&strongProvider->stats_mutex);
                    strongProvider->stats.packet_errors++;
                    pthread_mutex_unlock(&strongProvider->stats_mutex);
                    continue;
                }
                
                // Parse basic flow information from packet
                if (packet.flow.ip_version == 4 && packet.length >= 20) {
                    LOG_TRACE("Parsing IPv4 header");
                    // IPv4 header parsing
                    const uint8_t *ip_header = packet.data;
                    
                    // Validate IPv4 header
                    uint8_t version = (ip_header[0] >> 4) & 0x0F;
                    if (version != 4) {
                        LOG_ERROR("IPv4 packet has invalid version: %d", version);
                        continue;
                    }
                    
                    packet.flow.protocol = ip_header[9];
                    memcpy(&packet.flow.src_ip, &ip_header[12], 4);
                    memcpy(&packet.flow.dst_ip, &ip_header[16], 4);
                    
                    struct in_addr src_addr = {.s_addr = packet.flow.src_ip};
                    struct in_addr dst_addr = {.s_addr = packet.flow.dst_ip};
                    
                    const char* protocol_name = "Unknown";
                    if (packet.flow.protocol == PROTO_TCP) protocol_name = "TCP";
                    else if (packet.flow.protocol == PROTO_UDP) protocol_name = "UDP";
                    else if (packet.flow.protocol == 1) protocol_name = "ICMP";
                    
                    LOG_TRACE("IPv4: %s -> %s, protocol=%d (%s)", 
                             inet_ntoa(src_addr), inet_ntoa(dst_addr),
                             packet.flow.protocol, protocol_name);
                    
                    // Parse port information if TCP/UDP
                    uint8_t ihl = (ip_header[0] & 0x0F) * 4;
                    if ((packet.flow.protocol == PROTO_TCP || packet.flow.protocol == PROTO_UDP) &&
                        packet.length >= ihl + 4) {
                        const uint8_t *transport = packet.data + ihl;
                        packet.flow.src_port = (transport[0] << 8) | transport[1];
                        packet.flow.dst_port = (transport[2] << 8) | transport[3];
                        
                        LOG_TRACE("Ports: %d -> %d", packet.flow.src_port, packet.flow.dst_port);
                    } else if (packet.flow.protocol == PROTO_TCP || packet.flow.protocol == PROTO_UDP) {
                        LOG_WARN("Insufficient packet length for %s port parsing: %zu bytes (IHL=%d)", 
                                protocol_name, packet.length, ihl);
                    }
                } else if (packet.flow.ip_version == 6 && packet.length >= 40) {
                    // IPv6 header parsing with validation
                    const uint8_t *ip6_header = packet.data;
                    
                    // Validate IPv6 header structure
                    // Check traffic class and flow label (bytes 0-3)
                    uint8_t traffic_class = ((ip6_header[0] & 0x0F) << 4) | ((ip6_header[1] & 0xF0) >> 4);
                    uint32_t flow_label = ((ip6_header[1] & 0x0F) << 16) | (ip6_header[2] << 8) | ip6_header[3];
                    
                    // Validate payload length
                    uint16_t payload_length = (ip6_header[4] << 8) | ip6_header[5];
                    if (payload_length > (packet.length - 40)) {
                        // Invalid payload length - packet is malformed
                        LOG_DEBUG("Invalid IPv6 payload length: %u > %zu", 
                                 payload_length, packet.length - 40);
                        continue; // Skip this packet
                    }
                    
                    // Get next header (protocol)
                    packet.flow.protocol = ip6_header[6];
                    
                    // Validate hop limit (must not be 0)
                    uint8_t hop_limit = ip6_header[7];
                    if (hop_limit == 0) {
                        LOG_DEBUG("IPv6 packet with zero hop limit");
                        continue; // Skip this packet
                    }
                    
                    // Safe copy of addresses (already bounds-checked)
                    // Get next header (protocol)
                    packet.flow.protocol = ip6_header[6];
                    packet.flow.ip_version = 6;
                    
                    // For IPv6, we need to handle differently since flow uses uint32_t
                    // We'll extract the IPv4-mapped portion or use a hash for tracking
                    // Check if destination is IPv4-mapped IPv6 (::ffff:x.x.x.x)
                    static const uint8_t ipv4_mapped_prefix[12] = {0,0,0,0,0,0,0,0,0,0,0xFF,0xFF};
                    if (memcmp(&ip6_header[24], ipv4_mapped_prefix, 12) == 0) {
                        // IPv4-mapped destination - extract the IPv4 addresses
                        memcpy(&packet.flow.src_ip, &ip6_header[20], 4);  // Last 4 bytes of src
                        memcpy(&packet.flow.dst_ip, &ip6_header[36], 4);  // Last 4 bytes of dst  
                    } else {
                        // Pure IPv6 - use a hash of the address for tracking
                        uint32_t src_hash = 0, dst_hash = 0;
                        for (int i = 0; i < 16; i += 4) {
                            src_hash ^= *(uint32_t*)&ip6_header[8 + i];
                            dst_hash ^= *(uint32_t*)&ip6_header[24 + i];
                        }
                        packet.flow.src_ip = src_hash;
                        packet.flow.dst_ip = dst_hash;
                    }
                    
                    // Validate that source address is not multicast (first byte != 0xFF)
                    if (ip6_header[8] == 0xFF) {
                        LOG_DEBUG("IPv6 packet with multicast source address");
                        continue; // Skip this packet
                    }
                    
                    // Parse port information if TCP/UDP with proper bounds checking
                    if ((packet.flow.protocol == PROTO_TCP || packet.flow.protocol == PROTO_UDP) &&
                        packet.length >= 44 && payload_length >= 4) {
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