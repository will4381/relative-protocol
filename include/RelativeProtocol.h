//
//  RelativeProtocol.h
//  RelativeProtocol
//
//  iOS VPN framework using NetworkExtension
//  Clean, working implementation - no fake/placeholder modules
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

// iOS-specific modules
#include "ios_vpn.h"
#include "packet/tunnel_provider.h"
#include "packet/buffer_manager.h"

// Network protocol handling
#include "dns/resolver.h"
#include "tcp_udp/connection_manager.h"
#include "nat64/translator.h"

// Utilities
#include "metrics/ring_buffer.h"

#endif /* RelativeProtocol_h */