//
//  RelativeProtocol.h
//  RelativeProtocol
//
//  iOS-only VPN framework using NetworkExtension
//  Copyright (c) 2024 RelativeProtocol. All rights reserved.
//  Licensed under GNU General Public License v3.0
//

#ifndef RelativeProtocol_h
#define RelativeProtocol_h

#import <Foundation/Foundation.h>

//! Project version number for RelativeProtocol.
FOUNDATION_EXPORT double RelativeProtocolVersionNumber;

//! Project version string for RelativeProtocol.
FOUNDATION_EXPORT const unsigned char RelativeProtocolVersionString[];

// Main VPN API
#include "api/relative_vpn.h"

// Core types and utilities
#include "core/types.h"
#include "core/logging.h"

// iOS-specific packet tunnel provider
#include "packet/tunnel_provider.h"
#include "packet/buffer_manager.h"

// Socket bridge for iOS NetworkExtension
#include "socket_bridge/bridge.h"

// DNS resolution and caching
#include "dns/resolver.h" 
#include "dns/cache.h"

// Connection management
#include "tcp_udp/connection_manager.h"

// Metrics and monitoring
#include "metrics/ring_buffer.h"

// Privacy and security
#include "privacy/guards.h"

// iOS reachability monitoring
#include "reachability/monitor.h"

// Performance utilities
#include "mtu/discovery.h"
#include "nat64/translator.h"
#include "classifier/tls_quic.h"

// iOS crash reporting
#include "crash/reporter.h"

#endif /* RelativeProtocol_h */