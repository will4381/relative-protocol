#import <NetworkExtension/NetworkExtension.h>
#import <Network/Network.h>
#include "api/relative_vpn.h"
#include "packet/tunnel_provider.h"

@interface RelativeVPNProvider : NEPacketTunnelProvider

@property (nonatomic, strong) tunnel_provider_t *tunnelProvider;
@property (nonatomic) vpn_handle_t vpnHandle;

@end

@implementation RelativeVPNProvider

- (void)startTunnelWithOptions:(NSDictionary<NSString *,NSObject *> *)options 
             completionHandler:(void (^)(NSError * _Nullable))completionHandler {
    
    NSLog(@"Starting RelativeVPN tunnel");
    
    // Initialize the VPN configuration
    vpn_config_t config = {0};
    strncpy(config.log_level, "info", sizeof(config.log_level) - 1);
    config.tunnel_mtu = 1500;
    config.metrics_buffer_size = 1000;
    config.dns_cache_size = 500;
    config.enable_nat64 = true;
    config.enable_dns_leak_protection = true;
    config.enable_ipv6_leak_protection = true;
    config.enable_kill_switch = true;
    config.enable_webrtc_leak_protection = true;
    
    // Add DNS servers (using CloudFlare and Google)
    config.dns_server_count = 2;
    config.dns_servers[0] = inet_addr("1.1.1.1");    // CloudFlare
    config.dns_servers[1] = inet_addr("8.8.8.8");    // Google
    
    // Start the comprehensive VPN
    vpn_result_t result = vpn_start_comprehensive(&config);
    if (result.status != VPN_SUCCESS) {
        NSError *error = [NSError errorWithDomain:@"RelativeVPN" 
                                             code:result.status 
                                         userInfo:@{NSLocalizedDescriptionKey: @"Failed to start VPN engine"}];
        completionHandler(error);
        return;
    }
    
    self.vpnHandle = result.handle;
    
    // Create and configure tunnel provider
    self.tunnelProvider = tunnel_provider_create();
    if (!self.tunnelProvider) {
        NSError *error = [NSError errorWithDomain:@"RelativeVPN" 
                                             code:-1 
                                         userInfo:@{NSLocalizedDescriptionKey: @"Failed to create tunnel provider"}];
        completionHandler(error);
        return;
    }
    
    // Configure packet flow
    if (!tunnel_provider_configure_packet_flow(self.tunnelProvider, self.packetFlow)) {
        NSError *error = [NSError errorWithDomain:@"RelativeVPN" 
                                             code:-2 
                                         userInfo:@{NSLocalizedDescriptionKey: @"Failed to configure packet flow"}];
        completionHandler(error);
        return;
    }
    
    // Configure network settings
    NEPacketTunnelNetworkSettings *settings = [[NEPacketTunnelNetworkSettings alloc] 
                                                initWithTunnelRemoteAddress:@"10.0.0.1"];
    
    // IPv4 settings
    NEIPv4Settings *ipv4Settings = [[NEIPv4Settings alloc] 
                                    initWithAddresses:@[@"10.0.0.2"] 
                                    subnetMasks:@[@"255.255.255.0"]];
    ipv4Settings.includedRoutes = @[
        [NEIPv4Route defaultRoute]
    ];
    settings.IPv4Settings = ipv4Settings;
    
    // IPv6 settings
    NEIPv6Settings *ipv6Settings = [[NEIPv6Settings alloc] 
                                    initWithAddresses:@[@"fd00::2"] 
                                    networkPrefixLengths:@[@64]];
    ipv6Settings.includedRoutes = @[
        [NEIPv6Route defaultRoute]
    ];
    settings.IPv6Settings = ipv6Settings;
    
    // DNS settings
    NEDNSSettings *dnsSettings = [[NEDNSSettings alloc] 
                                  initWithServers:@[@"1.1.1.1", @"8.8.8.8"]];
    dnsSettings.matchDomains = @[@""];
    settings.DNSSettings = dnsSettings;
    
    // MTU
    settings.MTU = @(config.tunnel_mtu);
    
    // Apply settings
    [self setTunnelNetworkSettings:settings completionHandler:^(NSError * _Nullable error) {
        if (error) {
            NSLog(@"Failed to set tunnel network settings: %@", error);
            completionHandler(error);
        } else {
            NSLog(@"RelativeVPN tunnel started successfully");
            completionHandler(nil);
        }
    }];
}

- (void)stopTunnelWithReason:(NEProviderStopReason)reason 
           completionHandler:(void (^)(void))completionHandler {
    
    NSLog(@"Stopping RelativeVPN tunnel, reason: %ld", (long)reason);
    
    // Stop the VPN engine
    if (self.vpnHandle != VPN_INVALID_HANDLE) {
        vpn_stop_comprehensive(self.vpnHandle);
        self.vpnHandle = VPN_INVALID_HANDLE;
    }
    
    // Cleanup tunnel provider
    if (self.tunnelProvider) {
        tunnel_provider_destroy(self.tunnelProvider);
        self.tunnelProvider = NULL;
    }
    
    completionHandler();
}

- (void)handleAppMessage:(NSData *)messageData 
       completionHandler:(void (^)(NSData * _Nullable))completionHandler {
    
    // Handle messages from the main app
    // This could be used for configuration updates, statistics requests, etc.
    
    if (messageData.length < 4) {
        completionHandler(nil);
        return;
    }
    
    uint32_t messageType;
    [messageData getBytes:&messageType length:sizeof(messageType)];
    
    switch (messageType) {
        case 1: { // Get statistics
            vpn_metrics_t metrics;
            if (vpn_get_metrics_comprehensive(self.vpnHandle, &metrics)) {
                NSData *response = [NSData dataWithBytes:&metrics length:sizeof(metrics)];
                completionHandler(response);
            } else {
                completionHandler(nil);
            }
            break;
        }
        
        case 2: { // Get crash stats
            crash_stats_t crashStats;
            if (vpn_get_crash_stats_comprehensive(self.vpnHandle, &crashStats)) {
                NSData *response = [NSData dataWithBytes:&crashStats length:sizeof(crashStats)];
                completionHandler(response);
            } else {
                completionHandler(nil);
            }
            break;
        }
        
        default:
            completionHandler(nil);
            break;
    }
}

- (void)sleepWithCompletionHandler:(void (^)(void))completionHandler {
    // Handle device sleep
    NSLog(@"RelativeVPN: Device going to sleep");
    completionHandler();
}

- (void)wake {
    // Handle device wake
    NSLog(@"RelativeVPN: Device waking up");
}

// Example of creating TCP connections for specific flows
- (void)createTCPConnectionForFlow:(const flow_tuple_t *)flow {
    if (!self.tunnelProvider || !flow) return;
    
    // Convert IP address to string
    char hostname[INET6_ADDRSTRLEN];
    if (flow->ip_version == 4) {
        inet_ntop(AF_INET, &flow->dst_ip.v4.addr, hostname, INET_ADDRSTRLEN);
    } else {
        inet_ntop(AF_INET6, flow->dst_ip.v6.addr, hostname, INET6_ADDRSTRLEN);
    }
    
    // Create TCP connection using tunnel provider
    tunnel_provider_create_tcp_connection(self.tunnelProvider, 
                                        self, 
                                        hostname, 
                                        flow->dst_port,
                                        ^(NWTCPConnection *connection) {
        if (connection) {
            NSLog(@"Created TCP connection to %s:%d", hostname, flow->dst_port);
            
            // Set up read handler
            [connection readDataWithCompletionHandler:^(NSData * _Nullable data, NSError * _Nullable error) {
                if (error) {
                    NSLog(@"TCP read error: %@", error);
                } else if (data) {
                    // Forward data back to tunnel
                    tunnel_provider_send_packet(self.tunnelProvider, data.bytes, data.length);
                }
            }];
        } else {
            NSLog(@"Failed to create TCP connection to %s:%d", hostname, flow->dst_port);
        }
    });
}

// Example of creating UDP sessions
- (void)createUDPSessionForFlow:(const flow_tuple_t *)flow {
    if (!self.tunnelProvider || !flow) return;
    
    // Convert IP address to string
    char hostname[INET6_ADDRSTRLEN];
    if (flow->ip_version == 4) {
        inet_ntop(AF_INET, &flow->dst_ip.v4.addr, hostname, INET_ADDRSTRLEN);
    } else {
        inet_ntop(AF_INET6, flow->dst_ip.v6.addr, hostname, INET6_ADDRSTRLEN);
    }
    
    // Create UDP session using tunnel provider
    tunnel_provider_create_udp_session(self.tunnelProvider,
                                     self,
                                     hostname,
                                     flow->dst_port,
                                     ^(NWUDPSession *session) {
        if (session) {
            NSLog(@"Created UDP session to %s:%d", hostname, flow->dst_port);
            
            // Set up read handler
            [session setReadHandler:^(NSArray<NSData *> * _Nullable datagrams, NSError * _Nullable error) {
                if (error) {
                    NSLog(@"UDP read error: %@", error);
                } else if (datagrams) {
                    for (NSData *datagram in datagrams) {
                        // Forward datagram back to tunnel
                        tunnel_provider_send_packet(self.tunnelProvider, datagram.bytes, datagram.length);
                    }
                }
            } maxDatagrams:NSUIntegerMax];
        } else {
            NSLog(@"Failed to create UDP session to %s:%d", hostname, flow->dst_port);
        }
    });
}

@end

// Additional helper functions for integration

// Function to inject packets from NEPacketTunnelProvider into the VPN engine
void inject_packet_from_tunnel(vpn_handle_t handle, const uint8_t *data, size_t length, int protocol_family) {
    if (handle == VPN_INVALID_HANDLE || !data || length == 0) return;
    
    packet_info_t packet = {0};
    packet.data = data;
    packet.length = length;
    packet.timestamp_ns = clock_gettime_nsec_np(CLOCK_MONOTONIC);
    
    // Basic flow parsing
    if (protocol_family == AF_INET && length >= 20) {
        packet.flow.ip_version = 4;
        const uint8_t *ip_header = data;
        packet.flow.protocol = ip_header[9];
        memcpy(&packet.flow.src_ip.v4.addr, &ip_header[12], 4);
        memcpy(&packet.flow.dst_ip.v4.addr, &ip_header[16], 4);
        
        if ((packet.flow.protocol == PROTO_TCP || packet.flow.protocol == PROTO_UDP) && length >= 28) {
            uint8_t ihl = (ip_header[0] & 0x0F) * 4;
            const uint8_t *transport = data + ihl;
            packet.flow.src_port = (transport[0] << 8) | transport[1];
            packet.flow.dst_port = (transport[2] << 8) | transport[3];
        }
    } else if (protocol_family == AF_INET6 && length >= 40) {
        packet.flow.ip_version = 6;
        const uint8_t *ip6_header = data;
        packet.flow.protocol = ip6_header[6];
        memcpy(&packet.flow.src_ip.v6.addr, &ip6_header[8], 16);
        memcpy(&packet.flow.dst_ip.v6.addr, &ip6_header[24], 16);
        
        if ((packet.flow.protocol == PROTO_TCP || packet.flow.protocol == PROTO_UDP) && length >= 48) {
            const uint8_t *transport = data + 40;
            packet.flow.src_port = (transport[0] << 8) | transport[1];
            packet.flow.dst_port = (transport[2] << 8) | transport[3];
        }
    }
    
    // Inject packet into VPN engine
    vpn_inject_packet_comprehensive(handle, &packet);
}