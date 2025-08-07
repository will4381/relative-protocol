//
//  RelativeProtocol-Bridging-Header.h
//  RelativeProtocol Swift Bridge
//
//  Use this header to expose RelativeProtocol C functions to Swift
//

#ifndef RelativeProtocol_Bridging_Header_h
#define RelativeProtocol_Bridging_Header_h

// Import the main RelativeProtocol framework
#import "RelativeProtocol.h"

// Explicitly import core modules for Swift access
#import "ios_vpn.h"
#import "dns/resolver.h" 
#import "tcp_udp/connection_manager.h"
#import "nat64/translator.h"
#import "core/types.h"

#endif /* RelativeProtocol_Bridging_Header_h */